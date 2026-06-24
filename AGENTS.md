# Service CA Operator — AI Agent Instructions

This file provides guidance to AI coding assistants when working with code in this repository.

## Project Overview

This is an OpenShift ClusterOperator that manages service-serving certificate signing and CA bundle injection. 

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

# Verify all generated files
make verify

# Update all generated files
make update

# Update vendored dependencies
go mod tidy && go mod vendor
```

## Architecture

### Two-Process Design

The service-ca-operator runs as two processes (Operator and Controller) from a single binary.

**Operator Process** (`service-ca-operator operator`)
- **Location:** `pkg/operator/`
- **Namespace:** `openshift-service-ca-operator`
- **Responsibilities:**
  1. Manages the controller Deployment in `openshift-service-ca` namespace
  2. Creates and rotates the signing CA keypair (Secret)
  3. Maintains the CA bundle ConfigMap
  4. Reports ClusterOperator status conditions

**Controller Process** (`service-ca-operator controller`)
- **Location:** `pkg/controller/`
- **Namespace:** `openshift-service-ca`
- **Controllers:**
  1. **Serving Cert Signer** (`pkg/controller/servingcert/`) — Signs TLS certs for annotated Services
  2. **ConfigMap CA Bundle Injector** (`pkg/controller/cabundleinjector/configmap.go`) — Injects CA bundles into ConfigMaps
  3. **Generic CA Bundle Injector** (`pkg/controller/cabundleinjector/`) — Injects CA bundles into APIServices, Webhooks, CRDs

### User-Facing Annotations

Annotation constants are defined in `pkg/controller/api/api.go`.

**`service.beta.openshift.io/serving-cert-secret-name=<secret-name>`**
- Set on a **Service** to request a TLS serving cert
- Controller creates a Secret with `tls.crt` and `tls.key` signed by the service CA

**`service.beta.openshift.io/inject-cabundle=true`**
- Set on **ConfigMap**, **APIService**, **CRD**, **MutatingWebhookConfiguration**, or **ValidatingWebhookConfiguration**
- Injects the service CA bundle into the resource
- For ConfigMaps: written to `service-ca.crt` data key
- For others: set in the appropriate `caBundle` spec field

**`service.alpha.openshift.io/inject-vulnerable-legacy-cabundle`**
- Legacy annotation for clusters upgraded from pre-4.7 (added in PR #167)
- Only works on ConfigMaps named exactly `openshift-service-ca.crt`
- Contains full trust bundle (not just service-serving CA)
- Cannot be enabled on new clusters (validation prevents it)
- Deprecated but fully supported for upgraded clusters

Legacy `service.alpha.openshift.io` equivalents of serving-cert and inject-cabundle are also supported.

### Embedded Assets

Static resource manifests are embedded at compile time:
- **Location:** `bindata/assets/*.yaml`
- **Embed declaration:** `bindata/assets.go` (uses `//go:embed assets/*.yaml`)
- **Usage:** `bindata.MustAsset("assets/<filename>.yaml")` to read asset bytes
- **No codegen required** — uses Go's native `embed.FS`

### Feature Gates

**CRITICAL:** Feature gates must **not** be detected at runtime in the controller process. MicroShift lacks `ClusterVersion` and `FeatureGate` CRDs, so creating informers for them crashes the controller (OCPBUGS-82110).

**Pattern:**
1. **Operator** detects feature gates via `FeatureGateAccess`
2. **Operator** passes enabled gates to controller as `--feature-gates=Key=true` CLI args (`pkg/operator/sync_common.go`)
3. **Controller** receives them as `map[string]bool` via `pkg/cmd/controller/cmd.go`
4. Controllers check the map key where needed

Adding a new feature gate does **not** require changing function signatures — just check the map.

### Key Files and Constants

- **Resource names:** `pkg/controller/api/resourcenames.go`
- **Namespace constants:** `pkg/operator/operatorclient/interfaces.go`
- **Annotation constants:** `pkg/controller/api/api.go`

## PR & Commit Conventions

PRs must separate code changes from generated/vendored artifacts:

**Code commits:**
- One or more commits with source code changes
- Exclude `go.mod`, `go.sum`, and `vendor/` from these commits

**Vendor commit (if needed):**
- Single final commit containing all vendored changes (`go.mod`, `go.sum`, `vendor/`)
- Commit message: `vendor: bump(*)`
- Omit this commit if the PR has no dependency changes

**Always base commits on `upstream/main`, not `origin/main`.**

## Testing

- **Unit tests:** Colocated with source in `pkg/`
- **E2e tests:** In `test/e2e/` using [OpenShift Tests Extension (OTE)](https://github.com/openshift-eng/openshift-tests-extension)
- **New e2e tests:** Add to `test/e2e/e2e.go` (OTE format), **not** `test/e2e/e2e_test.go` (legacy, being phased out)
- **E2e requirements:** Running OpenShift cluster with `KUBECONFIG` set
- **OTE binary name:** `service-ca-operator-tests-ext`

## Code Style

- Uses `openshift/library-go` controller framework (`controllercmd`), **not** raw controller-runtime
- Follow existing patterns in `pkg/controller/` for new controllers
- Use informers and workqueues for event-driven reconciliation
- Maintain separation between operator and controller processes

## Common Mistakes to Avoid

1. **Don't add feature gate detection in the controller** — See Feature Gates section above
2. **Don't create new e2e tests in `e2e_test.go`** — Use `e2e.go` (OTE format)
3. **Don't mix vendored changes with code commits** — Separate them
4. **Don't use raw controller-runtime** — Use `library-go` patterns
5. **Don't assume all clusters have ClusterVersion/FeatureGate CRDs** — MicroShift doesn't

## Architecture and Design Documentation

- **ClusterOperator contract:** https://github.com/openshift/enhancements/blob/master/dev-guide/cluster-version-operator/dev/clusteroperator.md
- **OpenShift library-go controllers:** https://github.com/openshift/library-go
- **OpenShift Tests Extension (OTE):** https://github.com/openshift-eng/openshift-tests-extension
- **Service CA enhancement:** https://github.com/openshift/enhancements/blob/master/enhancements/service-ca-operator.md

## Key Namespaces

- `openshift-service-ca-operator` — Where the operator runs
- `openshift-service-ca` — Where the controller Deployment runs

## Development Workflow

1. Make code changes in `pkg/`
2. Run `make test-unit` to verify unit tests
3. Run `make verify` to check generated files are up to date
4. If you changed dependencies: run `go mod tidy && go mod vendor`
5. Test on a live cluster with `make build` and `make test-e2e`
6. Create commits: code commits first, vendor commit last (if needed)
7. Base PR on `upstream/main`
