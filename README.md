# qmax-receipt

[Evidence & Trust](https://docs.qualitymax.io/evidence-trust/) · [QualityMax ecosystem](https://github.com/Quality-Max/qualitymax)

A shared, versioned Go schema for signed **Exposure Receipts**: per-run manifests of outbound requests recorded by an integrating application. Entries describe destination, category, byte size, and content SHA-256 rather than storing payload content.

## Scope and verification

- An integration must record its outbound requests. This library does not automatically observe all network traffic or prove that every request was recorded.
- `Verify` checks the signed manifest against its key. Establish trust in the signer separately; accepting a key supplied with an untrusted manifest does not authenticate its issuer.
- Destination and category metadata can themselves be sensitive. Review receipts before sharing them or comparing them with your own network logs.
- An exposure receipt is distinct from a test result or a verified-fix verdict. It does not establish application correctness.

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
path, err := r.Finalize()                   // signs + writes BaseDir/receipts/<id>.json

if err != nil {
    return err
}

// Offline verification (inside a function returning error):
r2, err := receipt.Load(path)
if err != nil {
    return err
}
if err := receipt.Verify(r2); err != nil {
    return err
}
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

[MIT](LICENSE).
