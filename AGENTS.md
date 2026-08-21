# AGENTS.md

## Cursor Cloud specific instructions

TruffleHog is a single Go CLI (module `github.com/trufflesecurity/trufflehog/v3`, entrypoint `main.go`). It is not a long-running server; "running the app" means building/running the binary or running the test suite. Standard commands live in the `Makefile`, `scripts/lint.sh`, and `README.md` — refer to those rather than duplicating them.

### Build / run
- Build: `CGO_ENABLED=0 go build -o /tmp/trufflehog .`
- Run against local code (README examples work): `go run . filesystem <path> --no-verification --results=verified,unverified` or `make run` (scans this repo via `git file://.`).
- The Go toolchain is the only hard dependency for build/run/unit-test. `go mod download` (the update script) refreshes modules.

### Lint
- `make lint` runs `scripts/lint.sh`, which auto-installs the pinned `golangci-lint` (version pinned in that script, kept in sync with `.github/workflows/lint.yml`) into `$(go env GOPATH)/bin` on first run, then runs it. First run downloads the linter; subsequent runs reuse it.

### Testing (important gotcha)
- Use `make test-community` in this environment. It passes with no external credentials and is exactly what CI runs for forks (`.github/workflows/test.yml` → `test-community`).
- Do NOT expect `make test` to fully pass here. Many `pkg/sources/*` and all `pkg/analyzer/analyzers/*` tests fetch live test secrets from Truffle Security's GCP Secret Manager and fail with `could not find default credentials` unless authenticated via GCP workload-identity federation (only available in the upstream `trufflesecurity/trufflehog` CI, not forks or generic environments). Some `pkg/sources/docker` tests also require a running Docker daemon.
- `make test-integration` (testcontainers) and `make protos` require a Docker daemon, which is not installed by default here.
- `-race` tests (`make test-race`) need `CGO_ENABLED=1` (a C toolchain is present).

### Man page
- If you add/rename/remove CLI flags or subcommands, regenerate with `make man` and commit `docs/man/trufflehog.1` (CI fails on a stale man page).
