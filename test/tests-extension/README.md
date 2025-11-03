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
| `./bin/service-ca-operator-tests-ext run-suite openshift/service-ca-operator/candidate` | Runs new tests under stability evaluation (NOT in CI jobs). |
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

## Test Maturity Levels

Tests in this project follow a maturity progression to ensure stability before being included in CI jobs. This prevents unstable tests from blocking PRs and OCP payload releases.

### Maturity Stages

| Stage | Label | Description | Included in CI? |
|-------|-------|-------------|-----------------|
| **Candidate** | `g.Label("candidate")` | New tests under stability evaluation. Run manually or in development environments. | ❌ No |
| **Conformance** | `g.Label("conformance", "parallel")` | Stable, production-ready tests that can run in parallel. | ✅ Yes |
| **Serial** | `g.Label("conformance", "serial")` | Stable tests that must run sequentially. | ✅ Yes |

### Adding a New Test

When adding a new test, **always start with the `candidate` label**:

```go
var _ = g.Describe("My New Feature", g.Label("candidate"), func() {
    g.It("should work correctly", func() {
        // test implementation
    })
})
```

### Promoting a Test from Candidate to Conformance

Before promoting a test to `conformance`, it must be proven stable:

1. **Run the test multiple times** - Use `/payload-aggregate` to run at least 5 times:
   - For `[Serial]` tests: `/payload-aggregate periodic-ci-openshift-release-master-ci-4.20-e2e-gcp-ovn-techpreview-serial 5`
   - For parallel tests: `/payload-aggregate periodic-ci-openshift-release-master-ci-4.20-e2e-gcp-ovn-techpreview 5`

2. **Verify all runs passed** - Check that there are no flakes or intermittent failures

3. **Update the label**:
   ```go
   // Change from:
   var _ = g.Describe("My New Feature", g.Label("candidate"), func() {

   // To:
   var _ = g.Describe("My New Feature", g.Label("conformance", "parallel"), func() {
   ```

4. **Update metadata**:
   ```bash
   make build-update
   ```

5. **Create a PR** with the promotion, including evidence of successful test runs

### Why This Process Matters

- **Prevents CI Disruption**: Unstable tests in CI can block PRs and delay releases
- **TRT Team Challenges**: Failed CI tests trigger scrutiny from the Test Readiness Team (TRT)
- **Payload Release Impact**: Blocking tests can prevent OCP payload releases
- **Developer Experience**: Reduces false negatives and builds confidence in the test suite

### Running Candidate Tests

Candidate tests are isolated in their own suite and not run in CI:

```bash
# Run all candidate tests
make run-suite SUITE=openshift/service-ca-operator/candidate

# Or use the binary directly
./bin/service-ca-operator-tests-ext run-suite openshift/service-ca-operator/candidate
```

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