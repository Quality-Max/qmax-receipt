# qmax-receipt

The **shared, versioned schema** behind QualityMax's "Receipts, not promises"
trust model. Every QualityMax agent that touches the network — the `qmax` CLI
(crawl / test execution / CI) and the `qmax-code` terminal agent — imports this
module and emits the **same** Exposure Receipt: a per-run, customer-held manifest
of every outbound request (destination, category, byte size, and content
SHA-256 — **never content**), signed with ed25519.

One schema, one signer, one `Verify`. A receipt written by either agent is
validated by the same code (and re-implementable in any language off the pinned
`receipt_version`).

## What it is / isn't

- **Is:** a tamper-evident record of *what could have left the boundary* — hashes
  and sizes, so the receipt itself is non-sensitive and safe to hand a security
  reviewer to diff against their own firewall logs.
- **Isn't:** proof of honesty. `Verify` proves **provenance** (this key produced
  this receipt), not that the agent declared everything. Trust roots in open
  auditable source + each agent's static egress guard + customer log-diffing —
  never the signature alone. Do not describe a signed receipt as "trustworthy."

## Usage

```go
import receipt "github.com/Quality-Max/qmax-receipt"

func init() {
    receipt.AgentVersion = version
    // qmax CLI keeps the default (~/.qamax); qmax-code overrides:
    // receipt.BaseDir = filepath.Join(home, ".qmax-code")
}

// Per run (a CLI command, a daemon assignment, a qmax-code session):
ctx, r := receipt.Begin(ctx, "crawl")     // or receipt.NewCurrent("cli")
// ...the agent's httpx RoundTripper calls r.Record(entry) for each request...
path, _ := r.Finalize()                   // signs + writes BaseDir/receipts/<id>.json

// Offline verification:
r2, _ := receipt.Load(path)
err := receipt.Verify(r2)
```

`Entry.Category` is a free-form string: this module never enumerates categories.
Each agent supplies its own taxonomy and classifier, then records a category
string. `Templatize` (id-collapsing) is shared here because every agent needs it.

## What lives here vs in each agent

| Here (shared contract) | Per-agent (in each repo) |
|------------------------|--------------------------|
| `Entry` / `Receipt` / `Summary` types | `Classify()` + category constants |
| run routing, `Record`, `Finalize` | `httpx` recording RoundTripper + static guard |
| ed25519 `sign` / `Verify` | `policy` runtime allow-list (warn/strict) |
| `Load` / `List`, `Templatize` | egress-site wiring |

## Schema version

`Version = "1"`. Bump only on a wire-format change. The signed payload is the
`encoding/json` marshal of the `Receipt` with `Signature` omitted — struct-field
order + sorted map keys make it deterministic and cross-language reproducible.

## License

TBD before publishing (see `docs/RECEIPT_SHARED_MODULE_SCOPE.md`). A permissive
license (Apache-2.0 / MIT) fits a verifiable schema contract better than the
FSL used for the agent binaries — the whole point is that anyone can verify.
