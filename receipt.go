// Package receipt implements the Exposure Receipt: a per-run, customer-held
// manifest of every outbound request an agent made — destination, category,
// byte size, and content SHA-256 (NOT content). It is the mechanism behind the
// "Receipts, not promises" trust model.
//
// This is the SHARED, versioned schema contract imported by every QualityMax
// agent that emits receipts (the `qmax` CLI and the `qmax-code` terminal
// agent). The wire format is pinned by Version; a verifier in any language can
// reproduce the signed bytes (see sign.go). Each agent supplies its own traffic
// taxonomy — this package treats Entry.Category as a free-form string and never
// enumerates categories.
//
// Quality commitments enforced here:
//   - Fail loud, never silent: a request with no receipt-bearing context records
//     into a process-global "current" run, then an "untracked" fallback (with a
//     one-time warning) — entries are never dropped.
//   - Concurrency-safe: the seq counter is per-receipt and the entry slice is
//     mutex-guarded, so concurrent goroutines never interleave or race.
//   - Deterministic signing: receipts are signed over encoding/json output,
//     whose field order (struct order) and map-key order (sorted) are stable.
//
// This package intentionally does NOT import net/http: it operates on plain
// strings, keeping all net/http usage inside each agent's httpx chokepoint.
package receipt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Version of the receipt schema. Bump only on a wire-format change; both agents
// and any external verifier key off this.
const Version = "1"

// BuildSHA identifies the agent build that produced a receipt. Override via
// -ldflags "-X github.com/Quality-Max/qmax-receipt.BuildSHA=<sha>".
var BuildSHA = "dev"

// AgentVersion is stamped into each receipt; set by the importing agent at init.
var AgentVersion = "dev"

// BaseDir is the directory under which receipts (BaseDir/receipts/) and the
// signing key (BaseDir/receipt_ed25519.seed) are stored. Defaults to ~/.qamax,
// preserving the qmax CLI's original layout; qmax-code sets this to ~/.qmax-code
// at init so the two agents keep separate identities and stores.
var BaseDir = defaultBaseDir()

func defaultBaseDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fall back to CWD-relative rather than panicking at package init.
		return ".qamax"
	}
	return filepath.Join(home, ".qamax")
}

// Entry is a single recorded outbound request. It stores a hash and size, never
// content — so the receipt itself is non-sensitive and safe to share.
type Entry struct {
	Seq        int       `json:"seq"`
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Path       string    `json:"path"` // templatized: /api/agent/{id}/crawl/{id}/snapshot
	Category   string    `json:"category"`
	Model      *string   `json:"model"`
	ReqBytes   int64     `json:"req_bytes"`
	ReqSHA256  string    `json:"req_sha256"`
	RespStatus int       `json:"resp_status"`
	RespBytes  int64     `json:"resp_bytes"`
	Allowed    bool      `json:"allowed"`
	Rule       string    `json:"rule"`
	Note       string    `json:"note,omitempty"` // e.g. "blocked-by-egress-policy", "transport-error: ..."
}

// Signature is the detached ed25519 signature over the receipt payload.
type Signature struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"` // base64 raw ed25519 public key — receipt is self-verifying
	Value     string `json:"value"`      // base64 signature over the canonical payload
}

// Receipt is one run's manifest. The Signature field is omitted while signing
// (omitempty), so the signed payload is everything else, deterministically.
type Receipt struct {
	ReceiptVersion string     `json:"receipt_version"`
	RunID          string     `json:"run_id"`
	RunKind        string     `json:"run_kind"`
	AgentVersion   string     `json:"agent_version"`
	AgentBuildSHA  string     `json:"agent_build_sha"`
	StartedAt      time.Time  `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	Destinations   []string   `json:"destinations"`
	Entries        []Entry    `json:"entries"`
	Summary        Summary    `json:"summary"`
	Signature      *Signature `json:"signature,omitempty"`

	mu  sync.Mutex
	seq int
}

// Summary is the at-a-glance roll-up a reviewer reads first.
type Summary struct {
	TotalRequests int            `json:"total_requests"`
	TotalReqBytes int64          `json:"total_req_bytes"`
	ByCategory    map[string]int `json:"by_category"`
	Violations    int            `json:"violations"`
}

type ctxKey struct{}

var (
	currentMu     sync.RWMutex
	current       *Receipt
	fallback      *Receipt
	fallbackOnce  sync.Once
	warnedNoRoute sync.Once
)

func newRunID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand failure is catastrophic for signing too; surface a stable marker.
		return "norand-" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(b[:])
}

func newReceipt(kind string) *Receipt {
	return &Receipt{
		ReceiptVersion: Version,
		RunID:          newRunID(),
		RunKind:        kind,
		AgentVersion:   AgentVersion,
		AgentBuildSHA:  BuildSHA,
		StartedAt:      time.Now().UTC(),
		Entries:        []Entry{},
		Summary:        Summary{ByCategory: map[string]int{}},
	}
}

// Begin creates a receipt and returns a context carrying it. Use this for
// concurrent work (each daemon assignment/crawl session, or a qmax-code session)
// so entries route to the right run regardless of the process-global current.
func Begin(ctx context.Context, kind string) (context.Context, *Receipt) {
	r := newReceipt(kind)
	return context.WithValue(ctx, ctxKey{}, r), r
}

// NewCurrent creates a receipt and installs it as the process-global current
// run. Use this for single-run-per-process work (CLI commands, the daemon
// control plane). Returns the receipt so the caller can Finalize it.
func NewCurrent(kind string) *Receipt {
	r := newReceipt(kind)
	currentMu.Lock()
	current = r
	currentMu.Unlock()
	return r
}

// FromContext resolves the active receipt: context first, then process-global
// current, then a fail-loud untracked fallback. It never returns nil and never
// drops an entry on the floor.
func FromContext(ctx context.Context) *Receipt {
	if ctx != nil {
		if r, ok := ctx.Value(ctxKey{}).(*Receipt); ok && r != nil {
			return r
		}
	}
	currentMu.RLock()
	c := current
	currentMu.RUnlock()
	if c != nil {
		return c
	}
	warnedNoRoute.Do(func() {
		log.Printf("WARN: egress recorded with no active receipt; routing to 'untracked' run. This is a wiring bug — every entry point should call receipt.Begin/NewCurrent.")
	})
	fallbackOnce.Do(func() { fallback = newReceipt("untracked") })
	return fallback
}

// Record appends an entry to the receipt, assigning a per-receipt sequence
// number. Safe for concurrent callers.
func (r *Receipt) Record(e Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	e.Seq = r.seq
	r.Entries = append(r.Entries, e)
}

// Finalize stamps the summary, signs, and writes the receipt to
// BaseDir/receipts/<run_id>.json. It returns the written path.
func (r *Receipt) Finalize() (string, error) {
	r.mu.Lock()
	now := time.Now().UTC()
	r.FinishedAt = &now
	r.recomputeSummaryLocked()
	r.mu.Unlock()

	// If this receipt is the installed current run, clear it.
	currentMu.Lock()
	if current == r {
		current = nil
	}
	currentMu.Unlock()

	if err := r.sign(); err != nil {
		return "", fmt.Errorf("sign receipt: %w", err)
	}

	dir, err := receiptsDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create receipts dir: %w", err)
	}
	path := filepath.Join(dir, r.RunID+".json")
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal receipt: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write receipt: %w", err)
	}
	return path, nil
}

func (r *Receipt) recomputeSummaryLocked() {
	s := Summary{ByCategory: map[string]int{}}
	hosts := map[string]struct{}{}
	for _, e := range r.Entries {
		s.TotalRequests++
		s.TotalReqBytes += e.ReqBytes
		s.ByCategory[e.Category]++
		if !e.Allowed {
			s.Violations++
		}
		if e.Host != "" {
			hosts[e.Host] = struct{}{}
		}
	}
	dests := make([]string, 0, len(hosts))
	for h := range hosts {
		dests = append(dests, h)
	}
	sort.Strings(dests)
	r.Destinations = dests
	r.Summary = s
}

func receiptsDir() (string, error) {
	if BaseDir == "" {
		return "", fmt.Errorf("receipt.BaseDir is empty")
	}
	return filepath.Join(BaseDir, "receipts"), nil
}
