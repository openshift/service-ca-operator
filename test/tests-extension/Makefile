# Get the directory where this Makefile is, and the repo root
DIR := $(strip $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST)))))
REPO_ROOT := $(shell git rev-parse --show-toplevel)

# Include build-machinery-go from the vendored copy in parent repo
include $(addprefix $(REPO_ROOT)/vendor/github.com/openshift/build-machinery-go/make/, \
	golang.mk \
)

# Override defaults for test extension binary
GO_PACKAGE := github.com/openshift-eng/openshift-tests-extension
GO_BUILD_BINDIR := $(CURDIR)/bin

# openshift-tests-extension uses different variable names than standard build-machinery-go
# It uses CommitFromGit (uppercase) instead of commitFromGit (lowercase)
# Override GO_LD_FLAGS to use the correct variable names
GO_LD_FLAGS :=-ldflags " \
	-X '$(GO_PACKAGE)/pkg/version.CommitFromGit=$(SOURCE_GIT_COMMIT)' \
	-X '$(GO_PACKAGE)/pkg/version.BuildDate=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')' \
	-X '$(GO_PACKAGE)/pkg/version.GitTreeState=$(SOURCE_GIT_TREE_STATE)' \
"

# Test-specific binary should exempt FIPS compliance
# GO_COMPLIANCE_POLICY="exempt_all" must only be used for test related binaries.
# It prevents various FIPS compliance policies from being applied to this compilation.
GO_COMPLIANCE_POLICY := exempt_all
export GO_COMPLIANCE_POLICY

# Metadata file location
METADATA := $(CURDIR)/.openshift-tests-extension/openshift_payload_service-ca-operator.json

# Override build target to create custom binary name
# build-machinery-go would use 'cmd' as the binary name, but we want 'service-ca-operator-tests-ext'
.PHONY: build
build: vendor
	@mkdir -p $(GO_BUILD_BINDIR)
	$(GO) build $(GO_MOD_FLAGS) $(GO_BUILD_FLAGS) $(GO_LD_FLAGS) -o $(GO_BUILD_BINDIR)/service-ca-operator-tests-ext ./cmd/...

.PHONY: vendor
vendor:
	$(GO) mod vendor

# Override clean to remove our custom binary
.PHONY: clean-binaries
clean-binaries:
	$(RM) $(GO_BUILD_BINDIR)/service-ca-operator-tests-ext

.PHONY: clean
clean: clean-binaries
	$(RM) -r $(GO_BUILD_BINDIR)

#SECTION Tests
.PHONY: run-suite #HELP Run tests by suite name and generate JUnit report (e.g., make run-suite SUITE=openshift/service-ca-operator/all ARTIFACT_DIR=/tmp/artifacts)
run-suite: build
	@if [ -z "$(SUITE)" ]; then \
		echo "Error: SUITE variable is required. Available suites:"; \
		echo "  - openshift/service-ca-operator/all"; \
		echo "  - openshift/service-ca-operator/conformance/parallel"; \
		echo "  - openshift/service-ca-operator/conformance/serial"; \
		echo "  - openshift/service-ca-operator/optional/slow"; \
		echo ""; \
		echo "Usage: make run-suite SUITE=openshift/service-ca-operator/all [ARTIFACT_DIR=/tmp/artifacts]"; \
		exit 1; \
	fi
	@ARTIFACT_DIR_FINAL=$${ARTIFACT_DIR:-$(CURDIR)}; \
	echo "Using ARTIFACT_DIR: $$ARTIFACT_DIR_FINAL"; \
	mkdir -p $$ARTIFACT_DIR_FINAL; \
	$(GO_BUILD_BINDIR)/service-ca-operator-tests-ext run-suite $(SUITE) -j $$ARTIFACT_DIR_FINAL/junit_$(shell date +%Y%m%d-%H%M%S).xml

#SECTION Metadata
.PHONY: update-metadata #HELP Build and run 'update-metadata' to generate test metadata
update-metadata: build
	$(GO_BUILD_BINDIR)/service-ca-operator-tests-ext update --component openshift:payload:service-ca-operator
	$(MAKE) clean-metadata

# Ensure TestID is unique over time.
# TestID is built over Product:Type:ComponentName:TestDescription
# (i.e. openshift:payload:service-ca-operator:TestName)
# Details:
# - https://github.com/openshift/enhancements/blob/master/enhancements/testing/openshift-tests-extension.md#test-id
# - https://github.com/openshift-eng/ci-test-mapping
#──────────────────────────────────────────────────────────────
# How to rename a test?
# 1. Run: make list-test-names
# 2. Find the current full test name (e.g. "[sig-abc] My test does XYZ")
# 3. Add a Ginkgo label: ginkgo.Label("original-name:[sig-abc] My test does XYZ"). if there is existing original-name label, please do not update the label again and keep it unchanged.
# 4. Change the test name string and run: make build-update
# **Example**
# It("should pass a renamed sanity check",
# 	Label("original-name:[sig-service-ca] OLMv1 should pass a trivial sanity check"),
# 	func(ctx context.Context) {
# 		Expect(len("test")).To(BeNumerically(">", 0))
# 	})
# Note: You only add the label once. Do not update it after future renames.
#──────────────────────────────────────────────────────────────
# How to delete a test?
# 1. Run: make list-test-names
# 2. In main.go add:
#    ext.IgnoreObsoleteTests(
#        "[sig-service-ca] My removed test name",
#    )
# 3. Delete the test code in your suite file (e.g. service-ca.go)
# 4. Run: make build-update.
# This will regenerate the metadata without the test entry.
#────────────────────────────────────────────────────────────────────
.PHONY: build-update #HELP Build and update metadata and sanitize output
build-update: build update-metadata

.PHONY: list-test-names #HELP Show current full test names
list-test-names: build
	@$(GO_BUILD_BINDIR)/service-ca-operator-tests-ext list -o names

# Remove 'codeLocations' to avoid absolute paths like:
# "/Users/$(USER)/go/src/.../service-ca.go:12"
# These are machine-specific and make the metadata non-idempotent.
# More info: https://issues.redhat.com/browse/TRT-2186
.PHONY: clean-metadata #HELP Remove 'codeLocations' from metadata JSON
clean-metadata:
	@echo "Cleaning metadata (removing codeLocations)..."
	@jq 'map(del(.codeLocations))' $(METADATA) > $(METADATA).tmp && mv $(METADATA).tmp $(METADATA)

.PHONY: verify-metadata #HELP To verify that the metadata was properly updated
verify-metadata: update-metadata
	@if ! git diff --exit-code $(METADATA); then \
		echo "ERROR: Metadata is out of date. Please run 'make build-update' and commit the result."; \
		exit 1; \
	fi

#SECTION Development
# Note: verify, update, tidy targets are provided by golang.mk from build-machinery-go
# This ensures consistency with all other OpenShift components

.PHONY: lint #HELP Run golangci linter (not configured for tests-extension)
lint:
	@echo "Linting not configured for tests-extension"

.PHONY: fix-lint #HELP Fix lint issues (not configured for tests-extension)
fix-lint:
	@echo "Linting not configured for tests-extension"
