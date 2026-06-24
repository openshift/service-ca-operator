# AI Agent Instructions for service-ca-operator

> Also read [ARCHITECTURE.md](ARCHITECTURE.md) for design decisions, [CONTRIBUTING.md](CONTRIBUTING.md) for PR workflow, [OWNERS](OWNERS) for reviewers/approvers.

## What This Repo Is

An OpenShift ClusterOperator that manages the **service-serving CA** — a cluster-scoped certificate authority that automatically provisions TLS certificates for in-cluster Services. The operator manages the CA keypair and deploys a controller that signs serving certificates and injects CA bundles into annotated resources.

Two-process architecture from a single binary (`service-ca-operator`):
- **Operator** (`pkg/operator/`): Manages the signing CA, controller Deployment lifecycle, and ClusterOperator status
- **Controller** (`pkg/controller/`): Signs TLS certs for annotated Services, injects CA bundles into ConfigMaps/APIServices/Webhooks/CRDs

## Repository Layout

```text
cmd/service-ca-operator/           Single binary, two subcommands: operator | controller
cmd/service-ca-operator-tests-ext/ OTE e2e test binary
pkg/operator/                      Operator process — CA lifecycle, deployment sync, status
pkg/controller/                    Controller process — serving cert signer, CA bundle injectors
pkg/controller/api/                Annotation constants, resource names
pkg/controller/cabundleinjector/   CA bundle injection into ConfigMaps, webhooks, CRDs, APIServices
pkg/controller/servingcert/        Serving cert signing controller
pkg/cmd/                           CLI wiring (cobra commands)
bindata/assets/                    Embedded static manifests (Go embed.FS)
manifests/                         CVO-managed manifests (operator deployment, RBAC, monitoring)
profile-patches/                   HyperShift / managed profile patches
test/e2e/                          E2e tests (OTE framework)
```

## Build and Test Commands

```bash
make build                                           # Build operator + OTE test binary
make test-unit                                        # Run all unit tests
go test ./pkg/operator/ -run TestName -count 1        # Single unit test
make test-e2e                                         # E2e tests (requires cluster + KUBECONFIG)
make verify                                           # Verify generated files
make update                                           # Update generated files
go mod tidy && go mod vendor                          # Update vendored dependencies
```

## Critical Rules

1. **Never create FeatureGate/ClusterVersion informers in the controller process.** MicroShift lacks these CRDs — informers for them crash the controller (OCPBUGS-82110). The operator detects feature gates and forwards them to the controller as `--feature-gates=Key=true` CLI args. See `pkg/operator/sync_common.go` and `pkg/cmd/controller/cmd.go`.

2. **Separate code commits from vendor commits.** PRs must keep source changes and vendored artifacts (`go.mod`, `go.sum`, `vendor/`) in separate commits. Vendor commit message: `vendor: bump(*)`.

3. **New e2e tests go in `test/e2e/e2e.go` (OTE format)**, not `test/e2e/e2e_test.go` (legacy, being phased out).

## Key Patterns

- **Embedded assets**: Static manifests in `bindata/assets/*.yaml` are embedded via Go's `embed.FS` (declared in `bindata/assets.go`). Access with `bindata.MustAsset("assets/<file>.yaml")`. No code generation step needed.
- **Feature gate forwarding**: Operator reads gates via `FeatureGateAccess` → sets `--feature-gates` args on controller Deployment → controller receives `map[string]bool` in `pkg/cmd/controller/cmd.go`. Adding a new gate means checking the map key where needed — no function signature changes.
- **Controller framework**: Uses `openshift/library-go` controller framework (`controllercmd`), not controller-runtime.
- **User-facing annotations**: Defined in `pkg/controller/api/api.go`. Both `service.beta.openshift.io` and legacy `service.alpha.openshift.io` prefixes are supported.

## What NOT to Do

- **Don't detect features at runtime in the controller** — no `ClusterVersion` or `FeatureGate` watches. MicroShift will crash. Use the CLI args forwarding pattern instead.
- **Don't use `go-bindata`** — the repo migrated to Go's native `embed.FS` (PR #326).
- **Don't modify `test/e2e/e2e_test.go`** for new tests — use `test/e2e/e2e.go` (OTE).
- **Don't mix code and vendor changes** in the same commit.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for full details including component overview, controller table, CA rotation lifecycle, manifest management, platform/topology behavior, and design decisions.

Key namespaces:
- `openshift-service-ca-operator`: Where the operator runs
- `openshift-service-ca`: Where the controller Deployment runs

Key constants:
- Resource names: `pkg/controller/api/resourcenames.go`
- Namespace constants: `pkg/operator/operatorclient/interfaces.go`
