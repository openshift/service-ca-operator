# Service CA Operator Tests Extension
========================

This repository contains the tests for the Service CA Operator for OpenShift.
These tests run against OpenShift clusters and are meant to be used in the OpenShift CI/CD pipeline.
They use the framework: https://github.com/openshift-eng/openshift-tests-extension

## How to Run the Tests Locally

| Command                                         | Description                                                              |
|-------------------------------------------------|--------------------------------------------------------------------------|
| `make build`                                    | Builds the Service CA Operator test binary.                             |
| `./bin/service-ca-operator-tests-ext info`     | Shows info about the test binary and registered test suites.             |
| `./bin/service-ca-operator-tests-ext list`     | Lists all available test cases.                                          |
| `./bin/service-ca-operator-tests-ext run-suite openshift/service-ca-operator/all` | Runs the full Service CA Operator test suite. |
| `./bin/service-ca-operator-tests-ext run-suite openshift/service-ca-operator/conformance/parallel` | Runs conformance tests that are parallel-safe (not Serial or Slow). |
| `./bin/service-ca-operator-tests-ext run-suite openshift/service-ca-operator/conformance/serial` | Runs conformance tests that must run serially (labeled [Serial]). |
| `./bin/service-ca-operator-tests-ext run-suite openshift/service-ca-operator/optional/slow` | Runs long-running tests (labeled [Slow]). |
| `./bin/service-ca-operator-tests-ext run-test -n <test-name>` | Runs one specific test. Replace <test-name> with the test's full name.   |


The tests can be run locally using the `service-ca-operator-tests-ext` binary against an OpenShift cluster or a vanilla Kubernetes cluster.
Features and checks which are OpenShift-specific will be skipped when running against a vanilla Kubernetes cluster.

Use the environment variable `KUBECONFIG` to point to your cluster configuration file such as:

```shell
KUBECONFIG=path/to/kubeconfig ./bin/service-ca-operator-tests-ext run-test -n <test-name>
```

To run tests that include tech preview features, 
you need a cluster with Service CA Operator installed and those features enabled.

### Local Test using Service CA Operator and OCP

1. Use the `Cluster Bot` to create an OpenShift cluster with Service CA Operator installed.

**Example:**

```shell
launch 4.20 gcp,techpreview
```

2. Set the `KUBECONFIG` environment variable to point to your OpenShift cluster configuration file.

**Example:**

```shell
mv ~/Downloads/cluster-bot-2025-10-01-082741.kubeconfig ~/.kube/cluster-bot.kubeconfig
export KUBECONFIG=~/.kube/cluster-bot.kubeconfig
```

3. Run the tests using the `service-ca-operator-tests-ext` binary.

**Example:**
```shell
./bin/service-ca-operator-tests-ext run-suite openshift/service-ca-operator/all
```

### Local Test using Service CA Operator and Kind

**Prerequisites:**

Install Service CA Operator before running the tests. 
You can use the `kind` tool to create a local Kubernetes cluster with Service CA Operator installed.
Furthermore, if you are using feature gates in your test you will need to
ensure that those are enabled in your cluster.

**Example:**

export KUBECONFIG=$HOME/.kube/config

```shell
$ ./bin/service-ca-operator-tests-ext run-suite openshift/service-ca-operator/all
[
  {
    "name": "[Jira:service-ca][sig-api-machinery] Service CA Operator should inject a CA bundle into an annotated configmap [Suite:openshift/service-ca-operator/conformance/parallel]",
    "lifecycle": "blocking",
    "duration": 1379,
    "startTime": "2025-10-22 02:47:46.633778 UTC",
    "endTime": "2025-10-22 02:47:48.013106 UTC",
    "result": "passed",
    "output": "  STEP: creating a new namespace for the test @ 10/22/25 10:47:46.635\n  STEP: creating a configmap with the inject-cabundle annotation @ 10/22/25 10:47:47.369\n  STEP: waiting for the CA bundle to be injected @ 10/22/25 10:47:47.584\n  STEP: verifying the injected CA bundle is not empty @ 10/22/25 10:47:47.794\n"
  },
  {
    "name": "[Jira:service-ca][sig-api-machinery] Service CA Operator should have a running operator and managed resources [Suite:openshift/service-ca-operator/conformance/parallel]",
    "lifecycle": "blocking",
    "duration": 1387,
    "startTime": "2025-10-22 02:47:46.635351 UTC",
    "endTime": "2025-10-22 02:47:48.022991 UTC",
    "result": "passed",
    "output": "  STEP: checking for the service-ca-operator deployment @ 10/22/25 10:47:46.637\n  STEP: checking for the service-ca controller-manager deployment @ 10/22/25 10:47:47.372\n  STEP: checking for the signing-key secret @ 10/22/25 10:47:47.589\n  STEP: checking for the openshift-service-ca.crt configmap @ 10/22/25 10:47:47.806\n"
  }
]
```

## Writing Tests

You can write tests in the `test/tests-extension/test/` directory. 
Please follow these guidelines:

1. Skip OpenShift-specific logic on vanilla Kubernetes

If your test requires OpenShift-only APIs (e.g., clusterversions.config.openshift.io), 
guard it using `env.Get().IsOpenShift` to ensure it skips gracefully when running 
on vanilla Kubernetes clusters:

```go
    if !env.Get().IsOpenShift {
        extlogs.Warn("Skipping test: not running on OpenShift")
        Skip("This test requires OpenShift APIs")
    }
```

Or, if used within helper functions:
```go
    if !env.Get().IsOpenShift {
        extlogs.Warn("Skipping feature capability check: not OpenShift")
        return
    }
```

This ensures compatibility when running tests in non-OpenShift environments such as KinD.

## Test Stability: Using Informing Tests

To prevent unstable tests from blocking PRs and OCP payload releases, we use the **Informing** decorator for new tests. This allows tests to run in CI, collect data in Sippy, but not fail the CI job if they fail.

### Why This Matters

**Real-world example**: In commit `87df21ba5` (TRT-2385), all tests had to be removed and replaced with a fake test because:
- Tests passed locally but failed in e2e CI
- TRT team demanded PR revert
- This blocked PR merges and nightly payloads
- Resulted in repetitive work and lost development time

The `Informing()` decorator prevents this by:
- ✅ Running tests in real CI environment (not just local)
- ✅ Collecting data in Sippy and Component Readiness dashboards
- ✅ NOT blocking CI jobs or payloads on failure
- ✅ Allowing iteration without TRT intervention

### Adding a New Test with Informing

**Always use `ote.Informing()` for new tests:**

```go
import (
    g "github.com/onsi/ginkgo/v2"
    o "github.com/onsi/gomega"
    ote "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
)

var _ = g.Describe("My New Feature", func() {
    g.It("should work correctly", ote.Informing(), g.Label("conformance", "parallel"), func() {
        // test implementation
        o.Expect(true).To(o.BeTrue())
    })
})
```

### Promoting an Informing Test to Blocking

Tests **cannot stay informing forever**. Plan to promote to blocking in the next release at the latest.

**Promotion criteria:**

1. **Check Sippy for pass rate** - Must show >95% success rate over multiple CI runs
   - View at: https://sippy.dptools.openshift.org/

2. **Verify no cluster destabilization** - Confirm test doesn't crash or corrupt clusters

3. **Remove the decorator**:
   ```go
   // Change from:
   g.It("my test", ote.Informing(), g.Label("conformance", "parallel"), func() {

   // To:
   g.It("my test", g.Label("conformance", "parallel"), func() {
   ```

4. **Update metadata**:
   ```bash
   make build-update
   ```

5. **Create a PR** with promotion, referencing Sippy data showing stability

### Test Lifecycle

```
┌──────────────────────┐
│ New Test             │
│ ote.Informing()      │  ← Runs in CI, collects data, doesn't block
└──────────┬───────────┘
           │ ✅ Sippy shows >95% pass rate
           │ ✅ Multiple releases of stability
           ▼
┌──────────────────────┐
│ Production Test      │
│ (no decorator)       │  ← Blocks CI on failure
└──────────────────────┘
```

### Benefits Over Other Approaches

| Approach | Problem |
|----------|---------|
| **Local testing only** | ❌ Can't catch CI-specific issues (timing, resources, infrastructure) |
| **Direct to CI** | ❌ Blocks payloads immediately (this caused TRT-2385) |
| **Isolated test suite** | ❌ No real CI data, slow iteration, manual testing burden |
| **`ote.Informing()`** | ✅ Best of both worlds: CI testing + no blocking |

## Development Workflow

- Add or update tests in: `test/tests-extension/test/`
- Run `make build` to build the test binary
- You can run the full suite or one test using the commands in the table above
- Before committing your changes:
    - Run `make update-metadata` or `make build-update`
    - Run `make verify` to check formatting, linting, and validation

**IMPORTANT** Ensure that you either test any new test with `/payload-aggregate`
to avoid issues with Sippy or other tools due flakes. Run at least 5 times.

**Examples**

- For `[Serial]` tests run: `/payload-aggregate periodic-ci-openshift-release-master-ci-4.20-e2e-gcp-ovn-techpreview-serial 5`
- For others run: `/payload-aggregate periodic-ci-openshift-release-master-ci-4.20-e2e-gcp-ovn-techpreview 5`

## How to Rename a Test

1. Run `make list-test-names` to see the current test names
2. Find the name of the test you want to rename
3. Add a Ginkgo label with the original name, like this:

```go
It("should pass a renamed sanity check",
    Label("original-name:[sig-service-ca] My Old Test Name"),
    func(ctx context.Context) {
        Expect(len("test")).To(BeNumerically(">", 0))
    })
```

4. Run `make build-update` to update the metadata

**Note:** Only add the label once. Do not update it again after future renames.

## How to Delete a Test

1. Run `make list-test-names` to find the test name
2. Add the test name to the `IgnoreObsoleteTests` block in `main.go`, like this:

```go
ext.IgnoreObsoleteTests(
    "[sig-service-ca] My removed test name",
)
```

3. Delete the test code from your suite (like `main.go`)
4. Run `make build-update` to clean the metadata

**WARNING**: Deleting a test may cause issues with Sippy https://sippy.dptools.openshift.org/sippy-ng/
or other tools that expected the Unique TestID tracked outside of this repository. [More info](https://github.com/openshift-eng/ci-test-mapping)
Check the status of https://issues.redhat.com/browse/TRT-2208 before proceeding with test deletions.

## E2E Test Configuration

Tests are configured in: [ci-operator/config/openshift/service-ca-operator](https://github.com/openshift/release/blob/master/ci-operator/config/openshift/service-ca-operator/)

Here is a CI job example:

```yaml
- as: e2e-aws-techpreview-saop-ext
  steps:
    cluster_profile: aws
    env:
      FEATURE_SET: TechPreviewNoUpgrade

      # Only enable 'watch-namespaces' monitor to avoid job failures from other default monitors 
      # in openshift-tests (like apiserver checks, alert summaries, etc). In this job, the selected 
      # Service CA Operator test passed, but the job failed because a default monitor failed. 
      #
      # 'watch-namespaces' is very lightweight and rarely fails, so it's a safe choice.
      # There is no way to fully disable all monitors, but we can use this option to reduce noise.
      #
      # See: ./openshift-tests run --help (option: --monitor)
      TEST_ARGS: --monitor=watch-namespaces

      TEST_SUITE: openshift/service-ca-operator/all
    test:
    - ref: openshift-e2e-test
    workflow: openshift-e2e-aws
```

This uses the `openshift-tests` binary to run Service CA Operator tests against a test OpenShift release.

It works for pull request testing because of this:

```yaml
releases:
  latest:
    integration:
      include_built_images: true
```

More info: https://docs.ci.openshift.org/docs/architecture/ci-operator/#testing-with-an-ephemeral-openshift-release

## Makefile Commands

| Target                   | Description                                                                  |
|--------------------------|------------------------------------------------------------------------------|
| `make build`             | Builds the test binary.                                                      |
| `make update-metadata`   | Updates the metadata JSON file.                                              |
| `make build-update`      | Runs build + update-metadata + cleans codeLocations.                         |
| `make verify`            | Runs formatting, vet, and linter.                                            |
| `make list-test-names`   | Shows all test names in the binary.                                          |
| `make clean-metadata`    | Removes machine-specific codeLocations from the JSON metadata. [More info](https://issues.redhat.com/browse/TRT-2186) |

**Note:** Metadata is stored in: `.openshift-tests-extension/openshift_payload_service-ca-operator.json`

## FAQ

### Why don't we have a Dockerfile for `service-ca-operator-tests-ext`?

We do not provide a Dockerfile for `service-ca-operator-tests-ext` because building and shipping a 
standalone image for this test binary would introduce unnecessary complexity.

Technically, it is possible to create a new OpenShift component just for the 
Service CA Operator tests and add a corresponding test image to the payload. However, doing so requires 
onboarding a new component, setting up build pipelines, and maintaining image promotion 
and test configuration — all of which adds overhead.

From the OpenShift architecture point of view:

1. Tests for payload components are part of the product. Many users (such as storage vendors, or third-party CNIs)
rely on these tests to validate that their solutions are compatible and conformant with OpenShift.

2. Adding new images to the payload comes with significant overhead and cost. 
It is generally preferred to include tests in the same image as the component 
being tested whenever possible.

### Why do we need to run `make update-metadata`?

Running `make update-metadata` ensures that each test gets a unique and stable **TestID** over time.

The TestID is used to identify tests across the OpenShift CI/CD pipeline and reporting tools like Sippy. 
It helps track test results, detect regressions, and ensures the correct tests are 
executed and reported.

This step is important whenever you add, rename, or delete a test.
More information:
- https://github.com/openshift/enhancements/blob/master/enhancements/testing/openshift-tests-extension.md#test-id
- https://github.com/openshift-eng/ci-test-mapping

### How to get help with OTE?

For help with the OpenShift Tests Extension (OTE), you can:
- Join the `#wg-openshift-tests-extension` Slack channel
- Review the [OpenShift Tests Extension documentation](https://github.com/openshift-eng/openshift-tests-extension)