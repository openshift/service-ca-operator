# Architecture: service-ca-operator

## Scope

Manages the **service-serving certificate authority** for OpenShift clusters. Owns the signing CA keypair, its rotation lifecycle, and controllers that sign serving certs and inject CA bundles. Does **not** manage the platform trust bundle, ingress certificates, or any other cluster CA.

## Namespace Map

| Namespace | Purpose |
|-----------|---------|
| `openshift-service-ca-operator` | Operator process runs here |
| `openshift-service-ca` | Controller Deployment (the operand) runs here |
| `openshift-config` | User-specified config (read-only) |
| `openshift-config-managed` | Machine-specified config; CA bundle is synced here |

## Component Overview

Single binary, two processes:

```
service-ca-operator operator    → pkg/operator/    → manages CA + controller Deployment
service-ca-operator controller  → pkg/controller/  → signs certs, injects bundles
```

The operator creates the signing CA Secret, maintains the CA bundle ConfigMap, syncs static resources from embedded assets, and manages the controller Deployment. The controller reads the CA from mounted Secrets/ConfigMaps and runs independent controllers.

## Controllers

| Controller | Package | Watches | Reconciles |
|-----------|---------|---------|------------|
| Serving Cert Signer | `servingcert/controller/` | Services, Secrets | Creates TLS Secrets for annotated Services |
| Serving Cert Updater | `servingcert/controller/` | Services, Secrets | Refreshes certs approaching expiry |
| ConfigMap CA Injector | `cabundleinjector/configmap.go` | ConfigMaps | Injects CA bundle into annotated ConfigMaps |
| APIService CA Injector | `cabundleinjector/apiservice.go` | APIServices | Sets `spec.caBundle` on annotated APIServices |
| Webhook CA Injectors | `cabundleinjector/admissionwebhook.go` | Mutating/ValidatingWebhookConfigs | Sets `caBundle` on annotated webhooks |
| CRD CA Injector | `cabundleinjector/crd.go` | CRDs | Sets conversion webhook `caBundle` |
| Legacy Vulnerable Injector | `cabundleinjector/configmap.go` | ConfigMaps named `openshift-service-ca.crt` | Injects legacy bundle for pre-4.7 upgraded clusters |

## Reconciliation Flow

```
Operator process:
  1. Sync namespace, SA, RBAC from embedded assets  (manageControllerNS, manageControllerResources)
  2. Create or rotate signing CA Secret              (manageSignerCA)
  3. Update CA bundle ConfigMap                       (manageSignerCABundle)
  4. Apply controller Deployment with feature gate    (manageDeployment)
     args and image overrides

Controller process (started by operator as a Deployment):
  1. CA bundle watcher loads caBundlePath, watches for file changes
  2. Serving cert signer: Service annotated → create Secret with signed cert
  3. CA bundle injectors: resource annotated → inject CA bundle bytes
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

## CA Rotation

The signing CA has a 26-month lifetime, designed around the 12-month maximum upgrade interval:

```
T+0m   CA-1 created (or rotated)
T+12m  Cluster upgraded, all pods restarted
T+13m  Automated rotation: CA-1 remaining < 13m → CA-2 created
T+24m  Cluster upgraded again, all pods restarted
T+26m  CA-1 expires (no impact — pods already restarted)
```

Rotation creates two intermediate certificates for trust bridging:
- **New CA signed by old key**: lets pre-rotation clients trust post-rotation serving certs
- **Old CA signed by new key**: included in the new bundle so post-rotation clients trust pre-rotation serving certs

Forced rotation is supported via `unsupportedConfigOverrides` with a reason annotation to prevent re-rotation.

## Manifest and Resource Management

- **CVO-managed** (`manifests/`): Operator Deployment, RBAC, monitoring, network policies — applied by the Cluster Version Operator during install/upgrade
- **Operator-applied** (`bindata/assets/`): Controller namespace, SA, RBAC, Deployment, signing Secret/ConfigMap templates — embedded via Go `embed.FS` and applied at runtime by the operator

## Platform/Topology Behavior

- **Default**: Controller and operator both run on control plane nodes.
- **HyperShift** (`ExternalTopologyMode`): Controller Deployment is scheduled on worker nodes instead of control plane (`shouldScheduleOnWorkers`)
- **IBM Cloud Managed**: Custom Deployment manifest with profile patches (`profile-patches/ibm-cloud-managed/`)
- **MicroShift**: No `ClusterVersion` or `FeatureGate` CRDs. Feature gates are forwarded via CLI args — never detected at runtime in the controller

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

## Dependencies

| Dependency | Role |
|-----------|------|
| `openshift/library-go` | Controller framework (`controllercmd`), crypto primitives, resource apply, feature gate access, PKI profiles |
| `openshift/api` | Operator API types (`operatorv1.ServiceCA`), feature gate definitions, PKI API types |
| `openshift/client-go` | Typed clients and informers for OpenShift APIs |
| `k8s.io/client-go` | Core Kubernetes clients, informers, workqueue |

## Design Decisions

1. **Two-process architecture from one binary.** The operator and controller run as separate processes (separate Deployments) but are built from a single binary with subcommands. This keeps the operator's cluster-scoped concerns (CA lifecycle, ClusterOperator status) isolated from the controller's high-volume work (cert signing, bundle injection).

2. **Feature gate forwarding via CLI args.** The operator detects feature gates using `FeatureGateAccess` (which requires `ClusterVersion`/`FeatureGate` CRDs) and injects them as `--feature-gates=Key=true` args on the controller Deployment. This avoids a hard dependency on CRDs that don't exist on MicroShift. The constraint was discovered via OCPBUGS-82110 when the controller crashed on MicroShift.

3. **Hand-written rotation with bidirectional trust bridging.** Service-CA does **not** use library-go's `certrotation` package. Instead, `pkg/operator/rotate.go` implements its own rotation that creates two intermediate CA certificates — one signing the old CA's public key with the new CA's key, and vice versa. This ensures both pre- and post-rotation serving certs are trusted by both pre- and post-rotation clients *without waiting for cert re-signing*. This is more sophisticated than library-go's approach of simple bundle concatenation with an overlap window.

4. **26-month CA lifetime avoids 10-year expiry problems.** CKAO's 10-year signers cause trust propagation failures at ~8 years when downstream components fail to reload updated CA bundles (OCPBUGS-60241). Service-CA's shorter 26-month lifetime ensures rotation aligns with the upgrade cycle, sidestepping this class of bug entirely.

5. **CA bundle file watcher.** The CA bundle injectors watch the bundle file on disk for changes rather than only loading it at startup. This ensures bundle updates from CA rotation propagate without requiring a controller restart (PR #329), addressing the trust propagation failures seen across the platform.

6. **Configurable PKI (TechPreview).** Service-CA was the first operator integrated with the configurable PKI initiative (OCPSTRAT-2271, PR #327). The rotation code was widened from RSA-only (`*rsa.PrivateKey`) to algorithm-agnostic (`crypto.Signer`) to support ECDSA key types. PKI profile resolution uses `library-go/pkg/pki.ResolveCertificateConfig` with certificate name `service-ca.service-serving-signer` for the CA and `service-ca.service-serving` for leaf certs.