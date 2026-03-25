# Service CA Operator — AI Assistant Guidelines

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Build everything (operator binary + OTE test binary)
make build

# Run unit tests
make test-unit

# Run a single unit test
go test ./pkg/operator/ -run TestSyncName -count 1

# Run e2e tests (requires cluster access)
make test-e2e

# Regenerate bindata (after modifying files in bindata/v4.0.0/)
# Output: pkg/operator/v4_00_assets/bindata.go (generated — never hand-edit)
make update-bindata

# Verify bindata is up-to-date
make verify-bindata

# Verify all generated files
make verify

# Update all generated files
make update

# Update vendored dependencies
go mod tidy && go mod vendor
```

## Architecture

This is an OpenShift ClusterOperator with a two-process architecture running from a single binary (`service-ca-operator`):

### Operator Process (`service-ca-operator operator`)
- **Package:** `pkg/operator/`
- Has two main responsibilities:
  1. **Operand lifecycle:** Manages the controller Deployment in the `openshift-service-ca` namespace, syncing static resources (namespace, service account, RBAC, deployment) from bindata
  2. **Signing CA management:** Creates and rotates the signing CA keypair (Secret) and maintains the CA bundle ConfigMap
- Reports the "service-ca" ClusterOperator status conditions

### Controller Process (`service-ca-operator controller`)
- **Package:** `pkg/controller/`
- Started by the operator as a Deployment; runs three controllers:
  1. **Serving Cert Signer** (`pkg/controller/servingcert/`): Signs TLS serving certs for Services annotated with `service.beta.openshift.io/serving-cert-secret-name`
  2. **ConfigMap CA Bundle Injector** (`pkg/controller/cabundleinjector/configmap.go`): Injects the CA bundle into ConfigMaps annotated with `service.beta.openshift.io/inject-cabundle=true`
  3. **Generic CA Bundle Injector** (`pkg/controller/cabundleinjector/`): Injects the CA bundle into APIServices, MutatingWebhookConfigurations, ValidatingWebhookConfigurations, and CRDs with the same annotation

### User-Facing Annotations
Users interact with the controller by annotating their resources. The annotation constants are defined in `pkg/controller/api/api.go`.

- **`service.beta.openshift.io/serving-cert-secret-name=<secret-name>`** — Set on a **Service** to request a TLS serving cert. The controller creates a Secret with the given name containing `tls.crt` and `tls.key` signed by the service CA.
- **`service.beta.openshift.io/inject-cabundle=true`** — Set on a **ConfigMap**, **APIService**, **CRD**, **MutatingWebhookConfiguration**, or **ValidatingWebhookConfiguration** to inject the service CA bundle. For ConfigMaps the bundle is written to the `service-ca.crt` data key; for the others it is set in the appropriate `caBundle` spec field.

Legacy `service.alpha.openshift.io` equivalents of both annotations are also supported.

**Vulnerable legacy injection:** The annotation `service.alpha.openshift.io/inject-vulnerable-legacy-cabundle` is a special case added in 4.8 (PR #167) to support clusters upgraded from pre-4.7. On those clusters, the `openshift-service-ca.crt` ConfigMap in each namespace was published by kube-controller-manager (via the `OPENSHIFT_USE_VULNERABLE_LEGACY_SERVICE_CA_CRT` env var) and contained more certificates than just the service-serving CA — it included the full trust bundle that was historically embedded in SA tokens. The legacy injector (`LegacyVulnerableConfigMapCABundleInjector` in `pkg/controller/cabundleinjector/configmap.go`) is intentionally scoped: it only injects into ConfigMaps named exactly `openshift-service-ca.crt`, and it yields to the preferred `inject-cabundle` or alpha `inject-cabundle` annotations if either is present. Key details:
  - **Cannot be enabled on new clusters.** Validation introduced in 4.8 prevents changing the `KubeControllerManager` cluster config's `useMoreSecureServiceCA` from `"true"` to `"false"`. The only way to reproduce the legacy annotation is to start with a 4.7 install and upgrade.
  - **Deprecated but not removed.** The annotation is fully supported for upgraded clusters that already have it, but it is a known vulnerability and customers are advised to migrate their workloads off of it. It may be removed in a future release.

### Key Namespaces
- `openshift-service-ca-operator`: Where the operator runs
- `openshift-service-ca`: Where the controller Deployment runs

### Key Constants
- Resource names: `pkg/controller/api/resourcenames.go`
- Namespace constants: `pkg/operator/operatorclient/interfaces.go`

## PR / Commit Conventions

PRs should separate code changes from generated/vendored artifacts:

**Code commits** — one or more commits with source code changes. Exclude `go.mod`, `go.sum`, `vendor/`, and generated files (like `bindata.go`) from these commits.

**Generated/vendor commit (if needed)** — a single final commit containing all generated and vendored changes. If a PR has no dependency or generated file changes, this commit is not needed. Contents and commit message by scenario:
- Vendor only (`go.mod`, `go.sum`, `vendor/`): `vendor: bump(*)`
- Bindata only (`pkg/operator/v4_00_assets/bindata.go`): `update bindata`
- Both vendor and bindata: `vendor: bump(*), update bindata`

Always base commits on `upstream/main`, not `origin/main`.

## Testing

- **Unit tests** are colocated with source in `pkg/`
- **E2e tests** are in `test/e2e/` and use the [OpenShift Tests Extension (OTE)](https://github.com/openshift-eng/openshift-tests-extension) framework
- New e2e tests must be added to `test/e2e/e2e.go` (OTE format), **not** `test/e2e/e2e_test.go` (legacy — being phased out)
- E2e tests require a running OpenShift cluster with `KUBECONFIG` set
- The OTE test binary is `service-ca-operator-tests-ext`

## Code Style

- Uses `openshift/library-go` controller framework (`controllercmd`), not raw controller-runtime.
