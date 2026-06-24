# Contributing to service-ca-operator

## Prerequisites

- Go 1.25+
- For e2e tests: access to an OpenShift cluster with `KUBECONFIG` set

## Development Workflow

1. Fork the repo and clone your fork
2. Create a feature branch from `main`
3. Make your changes and add or update tests
4. Build and test locally:
   ```bash
   make build
   make test-unit
   make verify
   ```
5. If you changed dependencies: `go mod tidy && go mod vendor`
6. Push your branch and open a PR

## Building

```bash
make build       # Build operator binary + OTE test binary
make verify      # Verify generated files are up to date
make update      # Regenerate files
```

## Testing

| Command | What It Runs |
|---------|-------------|
| `make test-unit` | All unit tests (colocated in `pkg/`) |
| `go test ./pkg/operator/ -run TestName -count 1` | Single unit test |
| `make test-e2e` | E2e tests (requires cluster + `KUBECONFIG`) |

New e2e tests must be added to `test/e2e/e2e.go` using the [OTE framework](https://github.com/openshift-eng/openshift-tests-extension). Do **not** add tests to `test/e2e/e2e_test.go` (legacy, being phased out).

## Pull Request Guidelines

- Keep PRs focused — one logical change per PR
- Reference JIRA tickets in PR title: `OCPBUGS-XXXXX: description`
- Include tests for new functionality
- **Separate code and vendor commits.** Source changes and vendored artifacts (`go.mod`, `go.sum`, `vendor/`) must be in separate commits. Vendor commit message: `vendor: bump(*)`
- PRs require `/lgtm` from a reviewer and `/approve` from an approver (see [OWNERS](OWNERS))

### Commit Message Style

This repo uses short prefix conventions:

```
fix: description of the fix
test/e2e: migrate test-name to OTE suite
docs: update contributing guide
vendor: bump(*)
```

## Areas Requiring Extra Care

- **Feature gates in the controller process**: Never create `FeatureGate` or `ClusterVersion` informers in `pkg/controller/`. MicroShift lacks these CRDs and the controller will crash. Use the operator → CLI args forwarding pattern instead (see [AGENTS.md](AGENTS.md)).
- **Embedded assets**: Static manifests use Go's native `embed.FS` (`bindata/assets/`). Do not use `go-bindata`.
- **Vendored dependencies**: Always commit vendor changes separately from source changes.

## Review and Approval

Reviews follow the standard OpenShift OWNERS model:

- **Reviewers** can `/lgtm` — listed in [OWNERS](OWNERS) and [OWNERS_ALIASES](OWNERS_ALIASES) (`control-plane-approvers`)
- **Approvers** can `/approve` — same set for this repo
- JIRA component: `service-ca`

## CI Pipeline

CI runs via Prow / ci-operator. The build image is configured in `.ci-operator.yaml`. Key checks:
- Unit tests (`make test-unit`)
- Build verification (`make build`)
- Generated file verification (`make verify`)
- E2e tests run against an OpenShift cluster
