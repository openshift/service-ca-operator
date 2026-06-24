# OpenShift Service CA Operator

Controller to mint and manage serving certificates for Kubernetes services. This is an [OpenShift ClusterOperator](https://github.com/openshift/enhancements/blob/master/enhancements/dev-guide/operators.md#what-is-an-openshift-clusteroperator) that manages a cluster-scoped certificate authority for automatic TLS provisioning.

The operator runs three controllers:

- **Serving cert signer** — Issues signed TLS certificates for Services annotated with `service.beta.openshift.io/serving-cert-secret-name`. [See the OKD documentation for usage.](https://docs.okd.io/latest/security/certificates/service-serving-certificate.html)
- **ConfigMap CA bundle injector** — Injects the CA bundle into ConfigMaps annotated with `service.beta.openshift.io/inject-cabundle=true` (key: `service-ca.crt`)
- **Generic CA bundle injector** — Injects the CA bundle into APIServices, MutatingWebhookConfigurations, ValidatingWebhookConfigurations, and CRDs annotated with the same annotation

## Quick Start

### Prerequisites

- Go 1.25+
- For e2e tests: access to an OpenShift cluster with `KUBECONFIG` set

### Building

```bash
make build       # Build operator binary + OTE test binary
```

### Running Tests

```bash
make test-unit                                        # All unit tests
go test ./pkg/operator/ -run TestName -count 1        # Single unit test
make test-e2e                                         # E2e tests (requires cluster)
```

### Running in a Cluster

See [Testing a ClusterOperator/Operand image in a cluster](https://github.com/openshift/enhancements/blob/master/dev-guide/operators.md#how-can-i-test-changes-to-an-openshift-operatoroperandrelease-component).

## OTE Test Framework

This repository uses the [OpenShift Tests Extension (OTE)](https://github.com/openshift-eng/openshift-tests-extension) framework. After `make build`:

```bash
# List suites and tests
./service-ca-operator-tests-ext list suites
./service-ca-operator-tests-ext list tests --suite=openshift/service-ca-operator/operator/serial

# Run a suite or test
./service-ca-operator-tests-ext run-suite openshift/service-ca-operator/operator/serial
./service-ca-operator-tests-ext run-test "test-name"

# Serial execution with JUnit output
./service-ca-operator-tests-ext run-suite openshift/service-ca-operator/operator/serial -c 1 --junit-path=/tmp/junit.xml
```

## Documentation

- [AGENTS.md](AGENTS.md) — AI agent instructions and architecture overview
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to submit changes
- [OWNERS](OWNERS) — Reviewers and approvers

## Related Repositories

- [openshift/library-go](https://github.com/openshift/library-go) — Shared controller framework
- [openshift/api](https://github.com/openshift/api) — OpenShift API types and CRD manifests
- [openshift/enhancements](https://github.com/openshift/enhancements) — Enhancement proposals and operator dev guide
