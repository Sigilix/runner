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
| OpenGrep | on | Native SARIF with Sigilix metadata. `opengrep-config` defaults to `p/security-audit,p/owasp-top-ten`. |
| ESLint | on | Safe mode by default: no repository config or plugins. Uses Sigilix-owned JavaScript/TypeScript logic, promise, and security rules; typed TypeScript promise rules turn on when a TS config is detected. Use `eslint-mode: repo-config` only when you accept executing the caller repository's ESLint config/plugins in the scan job. |
| TypeScript Compiler | on | Converts `tsc --noEmit` diagnostics to SARIF when TypeScript configs are present. Bare external dependency-resolution noise is filtered, path-like unresolved imports stay visible as review signal, and declaration-file library checks are skipped to keep dependency noise bounded. |
| Ruff | on | Native SARIF with Sigilix metadata. |
| Brakeman | on | Native SARIF with Sigilix metadata for detected Rails applications. Caller Brakeman config and ignore files are bypassed so ignored warnings still reach review evidence. |
| Pylint | on | Converts Pylint JSON output to SARIF. Uses a Sigilix-owned high-confidence profile: Pylint fatal/error checks only, with caller config ignored and dependency-sensitive `import-error`/`no-member` disabled. |
| Flake8 | on | Converts Flake8 text output to SARIF when a `.flake8` marker is present. The config content is ignored; Sigilix runs high-confidence PyFlakes/parse checks only to avoid duplicating broad Ruff/Pylint style feedback. |
| Knip | on | Converts Knip JSON output to SARIF. Uses a Sigilix-owned JavaScript/TypeScript profile for unresolved imports, unlisted dependencies, and missing package-script binaries; broad unused-export/file reports are not enabled. |
| golangci-lint | on | Native SARIF with Sigilix metadata for Go repositories. Uses a runner-controlled standard linter profile and skips caller golangci config/plugins. |
| Buf | on | Converts Buf JSON-lines lint output to SARIF for Protobuf files. Uses a pinned Linux x86_64 Buf binary, verifies its SHA256 before execution, and runs with a runner-owned v2 MINIMAL config. Updating Buf requires changing both `BUF_VERSION` and `BUF_LINUX_X86_64_SHA256`. |
| SQLFluff | on | Converts SQLFluff JSON output to SARIF for SQL files using a runner-owned raw-templater config; CodeRabbit's documented low-signal ignored codes are excluded. |
| Prisma Lint | on | Converts Prisma Lint JSON output to SARIF for `.prisma` files when a non-JS Prisma Lint config is present. The pinned npm package integrity is verified before install. |
| RuboCop | on | Converts RuboCop JSON output to SARIF for Ruby files using a runner-owned config so caller plugin/gem loading is not executed. |
| PHPStan | on | Converts PHPStan JSON output to SARIF for PHP projects using a runner-owned config with no bootstrap/include directives. |
| PHPMD | on | Converts PHPMD JSON output to SARIF for PHP files using the low-noise `unusedcode` ruleset. |
| PHPCS | on | Converts PHPCS JSON output to SARIF when `phpcs.xml` or `phpcs.xml.dist` is present, using a runner-owned PSR-12 standard to avoid custom sniff execution. |
| Clippy | on | Converts Cargo/Clippy JSON compiler messages to SARIF for Rust projects with `Cargo.toml`, without enabling default Cargo features. |
| detekt | on | Native SARIF with Sigilix metadata for Kotlin files using a pinned detekt CLI jar and runner-owned config. |
| SwiftLint | on | Converts SwiftLint JSON output to SARIF for Swift files, with CodeRabbit's documented low-signal style rules disabled. |
| actionlint | on | Converts actionlint JSON to SARIF for GitHub Actions workflows. |
| ShellCheck | on | Converts ShellCheck `json1` output to SARIF. |
| YAMLlint | on | Converts YAMLlint parsable output to SARIF with relaxed defaults for config feedback. |
| markdownlint | on | Converts markdownlint JSON output to SARIF with Sigilix-controlled structural Markdown rules. |
| dotenv-linter | on | Converts dotenv-linter plain output to SARIF for `.env` file hygiene; assignment values are redacted during conversion. |
| checkmake | on | Converts checkmake JSON output to SARIF for Makefiles using runner-owned low-noise rules. |
| gitleaks | on | Native SARIF with Sigilix metadata. |
| osv-scanner | on | Native SARIF with Sigilix metadata. |
| Checkov | off | Native SARIF with Sigilix metadata. Opt-in IaC scanning. |
| Trivy | off | Native SARIF with Sigilix metadata. Opt-in filesystem vulnerability, secret, misconfiguration, and license scanning. |
| TruffleHog | off | Converts TruffleHog JSON output to SARIF. Secret verification is disabled in CI to avoid provider calls with discovered credentials; unverified or unverifiable hits are warning-level and metadata-only duplicates are collapsed without comparing secret values. |
| zizmor | on | Native SARIF with Sigilix metadata for GitHub Actions security scanning. |
| Hadolint | on | Native SARIF with Sigilix metadata for Dockerfile linting. |
| TFLint | on | Native SARIF with Sigilix metadata. Runs only when Terraform files are present. |
| Biome | on | Native SARIF with Sigilix metadata. Default-on Sigilix-controlled correctness linting for JS/TS and JSON; uses runner-owned config, bypasses caller ignore files, and skips common generated-output directories. |
| Oxlint | on | Native SARIF with Sigilix metadata. Default-on Sigilix-controlled correctness linting for JavaScript and TypeScript; uses runner-owned config, disables caller Oxlint config and ignore files, skips common generated-output directories, and checks pinned npm package integrity before scanning. |
| ast-grep | on | Native SARIF with Sigilix metadata. Default-on Sigilix-owned AST rules for high-confidence JavaScript and TypeScript async array logic bugs; verified npm tarballs are installed without package scripts before scanning. Caller ignore files are bypassed; common generated and vendor directories are still excluded. |
| Regal | on | Native SARIF with Sigilix metadata. Default-on Rego policy linting with runner-owned bug/import rules; style, performance, testing, and migration-preference feedback is disabled. |
| HTMLHint | on | Native SARIF with Sigilix metadata for HTML files. Uses runner-owned structural correctness rules, verifies the pinned npm tarball, and skips common generated-output directories. |
| Stylelint | on | Converts Stylelint JSON output to SARIF for CSS files. Uses runner-owned correctness rules, verifies the pinned npm tarball, and skips common generated-output directories. |

> **SIG-107:** `oxlint` now defaults to `true`. Set `oxlint: false` (boolean) in the caller workflow to suppress it.
> `biome` now defaults to `true`. Set `biome: false` (boolean) in the caller workflow to suppress it.
> `ast-grep` now defaults to `true`. Set `ast-grep: false` (boolean) in the caller workflow to suppress it.
> `pylint` now defaults to `true`. Set `pylint: false` (boolean) in the caller workflow to suppress it.
> `knip` now defaults to `true`. Set `knip: false` (boolean) in the caller workflow to suppress it.
> `tsc` now defaults to `true`. Set `tsc: false` (boolean) in the caller workflow to suppress it.
> `flake8`, `golangci-lint`, `htmlhint`, `stylelint`, and `tflint` now default to `true`.
> Set the matching boolean input to `false` in the caller workflow to suppress one of them.
> `markdownlint`, `dotenv-linter`, and `checkmake` now default to `true`. Set the matching
> boolean input to `false` in the caller workflow to suppress one of them.
> `regal` now defaults to `true`. Set `regal: false` (boolean) in the caller workflow to suppress it.
> `opengrep` and `brakeman` now default to `true`. Set the matching boolean input to `false`
> to suppress one of them; `opengrep-config` accepts comma-separated OpenGrep rulesets.
> `buf` now defaults to `true`. Set `buf: false` (boolean) in the caller workflow to suppress it.
> `sqlfluff`, `prisma-lint`, `rubocop`, `phpstan`, `phpmd`, `phpcs`, `clippy`, `detekt`,
> and `swiftlint` now default to `true`. Set the matching boolean input to `false` to suppress
> one of them.

These SIG-107 slices move the runner toward broader third-party tool parity. The Sigilix
metadata contract is currently attached to every listed tool.

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

Default-on tool booleans: `semgrep`, `eslint`, `ruff`, `actionlint`, `shellcheck`, `yamllint`,
`markdownlint`, `dotenv-linter`, `checkmake`, `gitleaks`, `osv-scanner`, `zizmor`, `hadolint`,
`biome`, `oxlint`, `ast-grep`, `pylint`, `flake8`, `knip`, `golangci-lint`, `htmlhint`,
`stylelint`, `tflint`, `regal`, `opengrep`, `brakeman`, `buf`, `sqlfluff`, `prisma-lint`,
`rubocop`, `phpstan`, `phpmd`, `phpcs`, `clippy`, `detekt`, `swiftlint`, and `tsc`.

Default-off opt-in tool booleans: `checkov`, `trivy`, and `trufflehog`.

Other useful inputs:

| Input | Default | Meaning |
| --- | --- | --- |
| `semgrep-config` | `auto` | Ruleset passed to `semgrep --config`. |
| `opengrep-config` | `p/security-audit,p/owasp-top-ten` | Comma-separated rulesets passed to OpenGrep as repeated `--config` values. |
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
- **Best-effort caller CI.** Tool findings and most tool availability failures do not fail the
  caller's CI; they degrade to SARIF metadata, empty SARIF runs, or warnings. Integrity or contract
  failures for a verified binary can fail the scan job so Sigilix does not trust unverified tool
  output. Malformed workflow/script changes in this runner still fail this repo's own CI.
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
