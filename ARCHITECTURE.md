# Architecture: service-ca-operator

## Overview

The service-ca-operator is an OpenShift ClusterOperator that automates the management of TLS certificates for internal cluster services. It provides two main capabilities:

1. **Automatic TLS certificate provisioning** — Services annotated with `service.beta.openshift.io/serving-cert-secret-name` automatically receive TLS certificates signed by a cluster-internal CA.
2. **CA bundle injection** — ConfigMaps and webhook resources annotated with `service.beta.openshift.io/inject-cabundle=true` automatically receive the cluster's service CA bundle for client-side certificate verification.

The operator runs as a two-process architecture from a single binary (`service-ca-operator`): an **operator** process that manages lifecycle and CA rotation, and a **controller** process that signs certificates and injects CA bundles.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Operator Process (openshift-service-ca-operator namespace)  │
│                                                             │
│  ┌────────────────────────────────────────────────────┐     │
│  │ pkg/operator/                                      │     │
│  │                                                    │     │
│  │  • Manages controller Deployment lifecycle         │     │
│  │  • Creates/rotates signing CA keypair (Secret)     │     │
│  │  • Maintains CA bundle ConfigMap                   │     │
│  │  • Reports ClusterOperator status                  │     │
│  │  • Detects feature gates → forwards to controller  │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ Deploys & manages
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Controller Process (openshift-service-ca namespace)         │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ pkg/controller/servingcert/                         │    │
│  │   Serving Cert Signer                               │    │
│  │   • Watches Services with serving-cert annotation   │    │
│  │   • Generates TLS cert/key signed by service CA     │    │
│  │   • Creates Secret with tls.crt and tls.key         │    │
│  │   • Supports headless services (SAN wildcards)      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ pkg/controller/cabundleinjector/                    │    │
│  │   CA Bundle Injector                                │    │
│  │   • ConfigMap injector (service-ca.crt data key)    │    │
│  │   • APIService injector (spec.caBundle field)       │    │
│  │   • CRD injector (conversion webhook caBundle)      │    │
│  │   • MutatingWebhookConfiguration injector           │    │
│  │   • ValidatingWebhookConfiguration injector         │    │
│  │   • Legacy vulnerable injection (4.7 upgrade path)  │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ Uses
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Signing CA Secret (openshift-service-ca namespace)          │
│   signing-key                                               │
│   • tls.crt — Current signing CA certificate                │
│   • tls.key — Current signing CA private key                │
│   • ca-bundle.crt — Full CA bundle (current + old CAs)      │
│   • intermediate-ca.crt — Post-rotation bridge cert         │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

### Certificate Provisioning

1. User creates a Service with annotation `service.beta.openshift.io/serving-cert-secret-name=my-tls`.
2. Serving Cert Signer controller observes the Service via informer.
3. Controller generates a TLS keypair with:
   - **CN**: `<service-name>.<namespace>.svc`
   - **SAN**: `<service-name>.<namespace>.svc`, `<service-name>.<namespace>.svc.cluster.local`
   - For **headless services**: adds wildcard SAN `*.<service-name>.<namespace>.svc` (for StatefulSet pod DNS)
4. Controller signs the certificate using the signing CA from `openshift-service-ca/signing-key`.
5. Controller creates a Secret in the Service's namespace with:
   - `tls.crt` — PEM-encoded certificate (leaf cert + issuing CA)
   - `tls.key` — PEM-encoded private key
   - Annotations tracking service UID, name, and expiry time
6. Service owner mounts the Secret in their pod to serve TLS traffic.

### CA Bundle Injection

1. User creates a ConfigMap (or APIService/CRD/webhook) with annotation `service.beta.openshift.io/inject-cabundle=true`.
2. CA Bundle Injector controller observes the resource via informer.
3. Controller reads the CA bundle from `openshift-service-ca/signing-key` Secret's `ca-bundle.crt` key.
4. Controller injects the bundle into:
   - **ConfigMap**: `data["service-ca.crt"]`
   - **APIService**: `spec.caBundle`
   - **CRD**: `spec.conversion.webhook.clientConfig.caBundle`
   - **MutatingWebhookConfiguration**: `webhooks[].clientConfig.caBundle`
   - **ValidatingWebhookConfiguration**: `webhooks[].clientConfig.caBundle`
5. Client workloads use the injected bundle to verify TLS connections to services with generated certificates.

### CA Rotation

CA rotation is triggered by one of:
- **Time-based**: CA approaching expiry (rotates when validity < 1 year remaining)
- **Forced**: Manual trigger via ServiceCA CR (`spec.forceRotation` with reason)
- **Deletion**: Signing secret deleted (operator recreates with new CA)

**Rotation process:**
1. Operator generates a new CA keypair.
2. Operator updates the signing secret:
   - `tls.crt` ← new CA
   - `tls.key` ← new private key
   - `ca-bundle.crt` ← new CA + old CA (trust-bridging bundle)
   - `intermediate-ca.crt` ← post-rotation bridge cert (if needed)
3. Operator updates the CA bundle ConfigMap in each namespace.
4. Controller observes the CA change (watches signing secret).
5. Controller regenerates all serving certificates signed by the old CA.
6. Controller re-injects the updated CA bundle into all annotated resources.
7. After a grace period (old certificates naturally expire), the old CA can be removed from the bundle.

## Deployment

### Operator Process
- **Namespace**: `openshift-service-ca-operator`
- **Deployment**: Managed by cluster-version-operator
- **Runs on**: Control plane nodes (tolerates master taints)
- **Command**: `service-ca-operator operator`

### Controller Process
- **Namespace**: `openshift-service-ca`
- **Deployment**: Managed by the operator process
- **Runs on**: Control plane nodes (tolerates master taints)
- **Command**: `service-ca-operator controller`
- **Replicas**: 1 (uses leader election for HA readiness)

### Static Assets
The operator syncs static resources from embedded YAML manifests:
- **Location**: `bindata/assets/*.yaml`
- **Embed**: Go native `//go:embed` directive (no code generation)
- **Resources**:
  - `ns.yaml` — openshift-service-ca namespace
  - `sa.yaml` — controller service account
  - `role.yaml`, `rolebinding.yaml` — namespace-scoped RBAC
  - `clusterrole.yaml`, `clusterrolebinding.yaml` — cluster-scoped RBAC
  - `deployment.yaml` — controller Deployment
  - `signing-secret.yaml` — signing CA Secret template
  - `signing-cabundle.yaml` — CA bundle ConfigMap template

## User-Facing Annotations

### Service Annotations
- **`service.beta.openshift.io/serving-cert-secret-name=<secret-name>`** — Request TLS certificate generation. The operator creates a Secret with the given name containing `tls.crt` and `tls.key`.
- **`service.beta.openshift.io/serving-cert-signed-by=<ca-common-name>`** — Added by the controller to track which CA signed the certificate. Used to determine when re-signing is needed.
- **`service.beta.openshift.io/serving-cert-generation-error`** — Error message if cert generation fails.
- **`service.beta.openshift.io/serving-cert-generation-error-num`** — Error retry count (stops retrying after max).

### Secret Annotations (Controller-Managed)
- **`service.beta.openshift.io/originating-service-uid`** — UID of the Service that requested this certificate.
- **`service.beta.openshift.io/originating-service-name`** — Name of the Service (for reverse lookups).
- **`service.beta.openshift.io/expiry`** — Certificate expiry time (RFC3339 format).

### CA Bundle Injection Annotations
- **`service.beta.openshift.io/inject-cabundle=true`** — Inject the service CA bundle into this resource. Supported on ConfigMap, APIService, CRD, MutatingWebhookConfiguration, ValidatingWebhookConfiguration.
- **`service.alpha.openshift.io/inject-vulnerable-legacy-cabundle=true`** — Legacy injection for clusters upgraded from pre-4.7. Only injects into ConfigMaps named exactly `openshift-service-ca.crt`. Yields to the preferred annotation if present. **Deprecated** and cannot be enabled on new clusters.

All annotations have legacy `service.alpha.openshift.io/*` equivalents that are still supported for backward compatibility.

## Feature Gates

Feature gates are detected by the **operator** process using the standard `FeatureGateAccess` mechanism from `openshift/library-go`. The operator forwards enabled gates to the controller Deployment as CLI arguments:

```
--feature-gates=FeatureName=true,OtherFeature=false
```

The controller receives these as a `map[string]bool` and threads the map through the call chain. This design avoids:
- Creating informers for `ClusterVersion` or `FeatureGate` CRDs in the controller (which would crash on MicroShift, where these CRDs don't exist — see OCPBUGS-82110)
- Requiring function signature changes when adding new feature gates

## Key Namespaces
- `openshift-service-ca-operator` — Operator process runs here
- `openshift-service-ca` — Controller process runs here; signing CA Secret lives here

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Two-process architecture | Separation of concerns: operator manages lifecycle and CA rotation (requires cluster-scoped permissions), controller signs certificates and injects bundles (can run with narrower permissions). |
| Embedded assets via `//go:embed` | No code generation step; assets embedded at compile time. Simplifies build and vendoring. |
| Annotation-driven API | No CRDs to install; works on any Kubernetes cluster. Easy for users to adopt (just add an annotation). |
| CA bundle includes old CAs after rotation | Trust-bridging: old certificates remain valid during rotation, preventing downtime. Clients using the bundle can verify both old and new certificates. |
| Feature gate forwarding via CLI args | Avoids creating informers for `FeatureGate` CRD in the controller, which crashes on MicroShift (OCPBUGS-82110). |
| Headless service SAN wildcards | Enables StatefulSet pods to serve TLS on their individual DNS names (`pod-0.service.ns.svc`, `pod-1.service.ns.svc`, etc.) using a single shared certificate. |
| Legacy vulnerable injection scoped to exact name | Limits blast radius of the deprecated trust bundle. Only ConfigMaps named `openshift-service-ca.crt` receive the wide bundle, and only on upgraded clusters. |
| Single binary, two subcommands | Simplifies distribution and versioning. Both processes use the same codebase and version. |

## Dependencies

- **openshift/library-go**: Controller framework (`controllercmd`), RBAC utilities, event recording, resource application (`resourceapply`)
- **openshift/client-go**: OpenShift API clients (config, operator)
- **k8s.io/client-go**: Kubernetes API clients, informers, listers
- **k8s.io/apiextensions-apiserver**: CRD client for CA bundle injection
- **k8s.io/kube-aggregator**: APIService client for CA bundle injection
- **openshift/library-go/pkg/crypto**: Certificate generation and signing utilities

## Testing

- **Unit tests**: Colocated with source in `pkg/`. Run with `make test-unit`.
- **E2E tests**: In `test/e2e/`, using the OpenShift Tests Extension (OTE) framework.
  - Tests are defined in `test/e2e/e2e.go` (OTE format, preferred).
  - Legacy tests in `test/e2e/e2e_test.go` are being phased out.
  - Binary: `service-ca-operator-tests-ext`
  - Run with: `make test-e2e` (requires `KUBECONFIG` pointing to a running OpenShift cluster)

**Example OTE test suites:**
- `serving-cert-annotation` — Certificate provisioning for annotated services
- `ca-bundle-injection-configmap` — CA bundle injection into ConfigMaps
- `apiservice-ca-bundle-injection` — CA bundle injection for APIServices
- `crd-ca-bundle-injection` — CA bundle injection for CRD conversion webhooks
- `mutatingwebhook-ca-bundle-injection` — CA bundle injection for MutatingWebhookConfigurations
- `validatingwebhook-ca-bundle-injection` — CA bundle injection for ValidatingWebhookConfigurations
- `refresh-CA` — CA regeneration after signing secret deletion
- `time-based-ca-rotation` — Time-based CA rotation when approaching expiry
- `forced-ca-rotation` — Forced CA rotation via ServiceCA CR
- `metrics` — Metrics collection and service CA expiry metrics

For full testing documentation, see [CONTRIBUTING.md](CONTRIBUTING.md).