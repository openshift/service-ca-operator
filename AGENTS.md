# AI Agent Instructions for service-ca-operator

> Also read [CONTRIBUTING.md](CONTRIBUTING.md) for PR workflow, [OWNERS](OWNERS) for reviewers/approvers.

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
go test ./pkg/operator/ -run TestSyncName -count 1    # Single unit test
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

This is an OpenShift ClusterOperator with a two-process architecture running from a single binary (`service-ca-operator`):

### Operator Process (`service-ca-operator operator`)
- **Package:** `pkg/operator/`
- Has two main responsibilities:
  1. **Operand lifecycle:** Manages the controller Deployment in the `openshift-service-ca` namespace, syncing static resources (namespace, service account, RBAC, deployment) from embedded assets
  2. **Signing CA management:** Creates and rotates the signing CA keypair (Secret) and maintains the CA bundle ConfigMap
- Reports the "service-ca" ClusterOperator status conditions

### Controller Process (`service-ca-operator controller`)
- **Package:** `pkg/controller/`
- Started by the operator as a Deployment; runs three controllers:
  1. **Serving Cert Signer** (`pkg/controller/servingcert/`): Signs TLS serving certs for Services annotated with `service.beta.openshift.io/serving-cert-secret-name`
  2. **ConfigMap CA Bundle Injector** (`pkg/controller/cabundleinjector/configmap.go`): Injects the CA bundle into ConfigMaps annotated with `service.beta.openshift.io/inject-cabundle=true`
  3. **Generic CA Bundle Injector** (`pkg/controller/cabundleinjector/`): Injects the CA bundle into APIServices, MutatingWebhookConfigurations, ValidatingWebhookConfigurations, and CRDs with the same annotation

### Embedded Assets
Static resource manifests are embedded using Go's native `embed.FS`:
- **Asset location:** `bindata/assets/*.yaml`
- **Embed declaration:** `bindata/assets.go` (uses `//go:embed assets/*.yaml`)
- **Usage:** `bindata.MustAsset("assets/<filename>.yaml")` to read asset bytes at runtime
- No code generation step is required — assets are embedded at compile time

### User-Facing Annotations
Users interact with the controller by annotating their resources. The annotation constants are defined in `pkg/controller/api/api.go`.

- **`service.beta.openshift.io/serving-cert-secret-name=<secret-name>`** — Set on a **Service** to request a TLS serving cert. The controller creates a Secret with the given name containing `tls.crt` and `tls.key` signed by the service CA.
- **`service.beta.openshift.io/inject-cabundle=true`** — Set on a **ConfigMap**, **APIService**, **CRD**, **MutatingWebhookConfiguration**, or **ValidatingWebhookConfiguration** to inject the service CA bundle. For ConfigMaps the bundle is written to the `service-ca.crt` data key; for the others it is set in the appropriate `caBundle` spec field.

Legacy `service.alpha.openshift.io` equivalents of both annotations are also supported.

**Vulnerable legacy injection:** The annotation `service.alpha.openshift.io/inject-vulnerable-legacy-cabundle` is a special case added in 4.8 (PR #167) to support clusters upgraded from pre-4.7. On those clusters, the `openshift-service-ca.crt` ConfigMap in each namespace was published by kube-controller-manager (via the `OPENSHIFT_USE_VULNERABLE_LEGACY_SERVICE_CA_CRT` env var) and contained more certificates than just the service-serving CA — it included the full trust bundle that was historically embedded in SA tokens. The legacy injector (`LegacyVulnerableConfigMapCABundleInjector` in `pkg/controller/cabundleinjector/configmap.go`) is intentionally scoped: it only injects into ConfigMaps named exactly `openshift-service-ca.crt`, and it yields to the preferred `inject-cabundle` or alpha `inject-cabundle` annotations if either is present. Key details:
  - **Cannot be enabled on new clusters.** Validation introduced in 4.8 prevents changing the `KubeControllerManager` cluster config's `useMoreSecureServiceCA` from `"true"` to `"false"`. The only way to reproduce the legacy annotation is to start with a 4.7 install and upgrade.
  - **Deprecated but not removed.** The annotation is fully supported for upgraded clusters that already have it, but it is a known vulnerability and customers are advised to migrate their workloads off of it. It may be removed in a future release.

### Feature Gates

Feature gates must **not** be detected at runtime in the controller process. MicroShift does not have the `ClusterVersion` or `FeatureGate` CRDs, so creating informers for them causes the controller to crash (see OCPBUGS-82110).

Instead, the **operator** detects feature gates via the standard `FeatureGateAccess` mechanism and forwards enabled gates to the controller Deployment as `--feature-gates=Key=true` CLI args (`pkg/operator/sync_common.go`). The controller receives them as a `map[string]bool` via `pkg/cmd/controller/cmd.go` and threads the map through the call chain. This means adding a new feature gate does **not** require changing function signatures — just check the map key where needed.

### Key Namespaces
- `openshift-service-ca-operator`: Where the operator runs
- `openshift-service-ca`: Where the controller Deployment runs

### Key Constants
- Resource names: `pkg/controller/api/resourcenames.go`
- Namespace constants: `pkg/operator/operatorclient/interfaces.go`

## PR / Commit Conventions

PRs should separate code changes from generated/vendored artifacts:

**Code commits** — one or more commits with source code changes. Exclude `go.mod`, `go.sum`, and `vendor/` from these commits.

**Vendor commit (if needed)** — a single final commit containing all vendored changes (`go.mod`, `go.sum`, `vendor/`). Commit message: `vendor: bump(*)`. If a PR has no dependency changes, this commit is not needed.

## Testing

- **Unit tests** are colocated with source in `pkg/`
- **E2e tests** are in `test/e2e/` and use the [OpenShift Tests Extension (OTE)](https://github.com/openshift-eng/openshift-tests-extension) framework
- New e2e tests must be added to `test/e2e/e2e.go` (OTE format), **not** `test/e2e/e2e_test.go` (legacy — being phased out)
- E2e tests require a running OpenShift cluster with `KUBECONFIG` set
- The OTE test binary is `service-ca-operator-tests-ext`

## Code Style

- Uses `openshift/library-go` controller framework (`controllercmd`), not raw controller-runtime.
