# Sigilix Runner

The reusable GitHub Actions workflow that powers [Sigilix](https://github.com/Sigilix)'s
deterministic-tool review lane and its self-hosted / private-code deployments.

> **Status:** live. `.github/workflows/scan.yml` is in production use (Sigilix dogfoods it on
> its own PRs). This public repo is its pinned, auditable home — pin your caller to a commit SHA.

## What it is

Sigilix's reviewer runs as a Cloudflare Worker, which cannot execute subprocesses. This repo
holds the **reusable workflow** that runs deterministic static-analysis tools **inside your own
CI**, normalizes their output to SARIF, and posts it back to Sigilix with a **GitHub-signed OIDC
receipt** so Sigilix can ground its review in real tool output, with cryptographic proof of
*where* and *what* ran. **Your source never leaves your infrastructure.**

Current staged catalog:

| Tool | Default | Notes |
| --- | --- | --- |
| Semgrep | on | Native SARIF with Sigilix metadata. `semgrep-config` defaults to `auto`. |
| ESLint | on | Safe mode by default: no repository config or plugins. Use `eslint-mode: repo-config` only when you accept executing the caller repository's ESLint config/plugins in the scan job. |
| Ruff | on | Native SARIF with Sigilix metadata. |
| actionlint | on | Converts actionlint JSON to SARIF for GitHub Actions workflows. |
| ShellCheck | on | Converts ShellCheck `json1` output to SARIF. |
| gitleaks | on | Native SARIF with Sigilix metadata. |
| osv-scanner | on | Native SARIF with Sigilix metadata. |

This is the first SIG-107 slice toward broader third-party tool parity. The Sigilix metadata
contract is currently attached to every listed tool.

## How to use

Add a workflow to your repository that calls the pinned reusable workflow:

```yaml
# .github/workflows/sigilix.yml
name: Sigilix
on: [pull_request]

# Restrictive workflow-level default; the id-token:write grant is scoped to the job below
# (so no other/future job in this workflow can mint a token).
permissions:
  contents: read

jobs:
  scan:
    permissions:
      contents: read
      id-token: write          # the ONLY elevated grant — to mint the OIDC receipt
    uses: Sigilix/runner/.github/workflows/scan.yml@<commit-sha>   # PIN to a SHA
    with:
      ingest-url: https://sigilix.dan-martinezjulio.workers.dev/runner/ingest
      oidc-audience: sigilix-runner-ingest
      semgrep-config: p/security-audit   # optional; defaults to "auto" (broader, noisier)
```

`ingest-url` + `oidc-audience` are Sigilix's configured ingest endpoint and token audience
(the values above); the worker rejects any token whose `aud` doesn't match. **Pin to a commit
SHA** (not a branch or tag): the receipt attests the exact tool version only when you pin, and
a moving ref cannot prove which version of the runner ran.

### Inputs

All tool booleans default to `true`: `semgrep`, `eslint`, `ruff`, `actionlint`, `shellcheck`,
`gitleaks`, and `osv-scanner`.

Other useful inputs:

| Input | Default | Meaning |
| --- | --- | --- |
| `semgrep-config` | `auto` | Ruleset passed to `semgrep --config`. |
| `eslint-mode` | `safe` | `safe` avoids repository config/plugins; `repo-config` opts in to the caller's ESLint config and plugins, which execute in the no-OIDC scan job. |
| `result-cap` | `500` | Maximum kept findings per Sigilix-managed tool run. Dropped counts are stored in SARIF metadata. |
| `sarif-byte-cap` | `7800000` | Maximum merged SARIF payload bytes before later runs are dropped. |

## Security model

- **No code egress.** The workflow runs in *your* CI; only normalized SARIF findings + the OIDC
  token are sent to Sigilix.
- **Token isolation.** Tool execution happens in a scan job without `id-token: write`. The ingest
  job has the OIDC grant, downloads only the SARIF artifact, and does not checkout source.
- **OIDC-signed receipts.** Each run requests a GitHub Actions OIDC token (`id-token: write`)
  bound to your `repository`, commit `sha`, and the called workflow ref. Sigilix verifies it
  (RS256 against GitHub's JWKS) plus a provenance gate before trusting any finding, and enforces
  single-use so a receipt can't be replayed.
- **Best-effort caller CI.** Tool findings and tool download failures do not fail the caller's CI;
  they degrade to SARIF metadata, empty SARIF runs, or warnings. Malformed workflow/script changes
  in this runner still fail this repo's own CI.
- **Coverage manifest.** Every run uploads and posts `scan-manifest.json` next to SARIF, recording
  each configured tool as `produced`, `empty`, `missing-output`, `invalid-output`, or `disabled`.
  Sigilix stores it with the OIDC receipt so green CI never has to mean "all tools ran."
- **Auditable.** This repository is public so you can read exactly what runs against your code.

## License

MIT — see [LICENSE](./LICENSE).

## Related

- **Sigilix worker** (private, `Sigilix/sigilix`): the OIDC verifier + provenance gate
  (`src/lib/runner-oidc/`) and the ingest endpoint (`POST /runner/ingest`) that consume the
  receipts this runner produces. Tracked under SIG-184.
