package receipt

import (
	"context"
	"testing"
)

// setTempBaseDir points BaseDir at a throwaway dir for the duration of a test,
// so the shared module never touches the developer's real ~/.qamax.
func setTempBaseDir(t *testing.T) {
	t.Helper()
	old := BaseDir
	BaseDir = t.TempDir()
	t.Cleanup(func() { BaseDir = old })
}

func TestRecordFinalizeLoadVerify(t *testing.T) {
	setTempBaseDir(t)

	ctx, r := Begin(context.Background(), "test-run")
	_ = ctx
	model := "claude-opus-4-8"
	r.Record(Entry{
		Method:    "POST",
		Host:      "api.qualitymax.io",
		Path:      Templatize("/api/agent/42/crawl/7/snapshot"),
		Category:  "behavioral-snapshot",
		Model:     &model,
		ReqBytes:  1024,
		ReqSHA256: "deadbeef",
		Allowed:   true,
		Rule:      "allow",
	})
	r.Record(Entry{
		Method:   "POST",
		Host:     "api.anthropic.com",
		Path:     Templatize("/v1/messages"),
		Category: "llm-prompt",
		ReqBytes: 512,
		Allowed:  true,
	})

	if got := r.EntryCount(); got != 2 {
		t.Fatalf("EntryCount = %d, want 2", got)
	}

	path, err := r.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.ReceiptVersion != Version {
		t.Errorf("ReceiptVersion = %q, want %q", loaded.ReceiptVersion, Version)
	}
	if loaded.Summary.TotalRequests != 2 {
		t.Errorf("Summary.TotalRequests = %d, want 2", loaded.Summary.TotalRequests)
	}
	if loaded.Summary.TotalReqBytes != 1536 {
		t.Errorf("Summary.TotalReqBytes = %d, want 1536", loaded.Summary.TotalReqBytes)
	}
	// Path must be templatized — no raw ids leaked.
	if loaded.Entries[0].Path != "/api/agent/{id}/crawl/{id}/snapshot" {
		t.Errorf("Path = %q, not templatized", loaded.Entries[0].Path)
	}

	if err := Verify(loaded); err != nil {
		t.Fatalf("Verify (untampered): %v", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	setTempBaseDir(t)

	_, r := Begin(context.Background(), "test-run")
	r.Record(Entry{Method: "GET", Host: "h", Path: "/p", Category: "control", Allowed: true})
	path, err := r.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Mutate a recorded byte-count after signing; the signature must no longer verify.
	loaded.Entries[0].ReqBytes = 999999
	if err := Verify(loaded); err == nil {
		t.Fatal("Verify accepted a tampered receipt; want failure")
	}
}

func TestUntrackedFallbackNeverDrops(t *testing.T) {
	setTempBaseDir(t)
	// No Begin/NewCurrent: FromContext must still return a live receipt.
	r := FromContext(context.Background())
	if r == nil {
		t.Fatal("FromContext returned nil; entries would be dropped")
	}
	r.Record(Entry{Method: "GET", Host: "h", Path: "/p", Category: "control"})
	if r.EntryCount() == 0 {
		t.Fatal("untracked fallback dropped the entry")
	}
}
