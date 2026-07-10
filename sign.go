package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// keyFileName holds the raw 32-byte ed25519 seed (base64) under BaseDir.
const keyFileName = "receipt_ed25519.seed"

// sign computes a detached ed25519 signature over the receipt's canonical JSON
// (everything except the signature itself) and attaches it.
//
// Determinism note: the signed bytes are encoding/json output of the Receipt
// with Signature=nil (dropped via omitempty). Go's json marshals struct fields
// in declaration order and map keys in sorted order, both documented and stable,
// so the same receipt always yields the same bytes — and a verifier in another
// language can reproduce them.
func (r *Receipt) sign() error {
	priv, err := loadOrCreateKey()
	if err != nil {
		return err
	}
	payload, err := r.signablePayload()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, payload)
	r.Signature = &Signature{
		Alg:       "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		Value:     base64.StdEncoding.EncodeToString(sig),
	}
	return nil
}

// signablePayload marshals the receipt with the signature omitted.
func (r *Receipt) signablePayload() ([]byte, error) {
	saved := r.Signature
	r.Signature = nil
	data, err := json.Marshal(r)
	r.Signature = saved
	if err != nil {
		return nil, fmt.Errorf("marshal signable payload: %w", err)
	}
	return data, nil
}

// Verify checks a receipt's embedded signature against its embedded public key.
// It proves PROVENANCE (this key produced this receipt), not honesty — trust
// roots in open source + the static egress guard + the customer diffing the
// receipt against their own firewall logs, never the signature alone.
func Verify(r *Receipt) error {
	if r.Signature == nil {
		return errors.New("receipt has no signature")
	}
	if r.Signature.Alg != "ed25519" {
		return fmt.Errorf("unsupported signature alg: %s", r.Signature.Alg)
	}
	pub, err := base64.StdEncoding.DecodeString(r.Signature.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("bad public key size: %d", len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	payload, err := r.signablePayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

func keyPath() (string, error) {
	if BaseDir == "" {
		return "", fmt.Errorf("receipt.BaseDir is empty")
	}
	return filepath.Join(BaseDir, keyFileName), nil
}

// loadOrCreateKey returns the agent's persistent ed25519 private key, generating
// and persisting one (0600) on first use.
func loadOrCreateKey() (ed25519.PrivateKey, error) {
	path, err := keyPath()
	if err != nil {
		return nil, err
	}
	if data, err := os.ReadFile(path); err == nil {
		seed, derr := base64.StdEncoding.DecodeString(string(data))
		if derr == nil && len(seed) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed), nil
		}
		// Corrupt key file: fail loud rather than silently minting a new identity.
		return nil, fmt.Errorf("receipt key at %s is unreadable/corrupt; refusing to silently rotate identity", path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read receipt key: %w", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate receipt key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed)), 0o600); err != nil {
		return nil, fmt.Errorf("write receipt key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
