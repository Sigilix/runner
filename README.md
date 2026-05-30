# Sigilix Runner

The reusable GitHub Actions workflow that powers [Sigilix](https://github.com/Sigilix)'s
deterministic-tool review lane and its self-hosted / private-code deployments.

> **Status:** active development. The reusable workflow (`.github/workflows/scan.yml`) is
> being finalized; this repo is the pinned, auditable home it will live in.

## What it is

Sigilix's reviewer runs as a Cloudflare Worker, which cannot execute subprocesses. This repo
holds the **reusable workflow** that runs the deterministic tools (Semgrep/OpenGrep, ESLint,
Ruff, actionlint, ShellCheck) **inside your own CI**, normalizes their output to SARIF, and
posts it back to Sigilix with a **GitHub-signed OIDC receipt** — so Sigilix can ground its
review in real tool output, with cryptographic proof of *where* and *what* ran. **Your source
never leaves your infrastructure.**

## How to use

Add a workflow to your repository that calls the pinned reusable workflow:

```yaml
# .github/workflows/sigilix.yml
name: Sigilix
on: [pull_request]
permissions:
  contents: read
  id-token: write          # lets the runner mint its OIDC receipt
jobs:
  scan:
    uses: sigilix/runner/.github/workflows/scan.yml@<commit-sha>   # PIN to a SHA
```

**Pin to a commit SHA** (not a branch or tag): the receipt attests the exact tool version only
when you pin, and a moving ref cannot prove which version of the runner ran.

## Security model

- **No code egress.** The workflow runs in *your* CI; only normalized SARIF findings + the OIDC
  token are sent to Sigilix.
- **OIDC-signed receipts.** Each run requests a GitHub Actions OIDC token (`id-token: write`)
  bound to your `repository`, commit `sha`, and the called workflow ref. Sigilix verifies it
  (RS256 against GitHub's JWKS) plus a provenance gate before trusting any finding, and enforces
  single-use so a receipt can't be replayed.
- **Auditable.** This repository is public so you can read exactly what runs against your code.

## License

MIT — see [LICENSE](./LICENSE).

## Related

- **Sigilix worker** (private, `Sigilix/sigilix`): the OIDC verifier + provenance gate
  (`src/lib/runner-oidc/`) and the ingest endpoint (`POST /runner/ingest`) that consume the
  receipts this runner produces. Tracked under SIG-184.
