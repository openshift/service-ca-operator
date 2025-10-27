all: build
.PHONY: all

GO_PACKAGE := github.com/openshift/service-ca-operator
GO_LD_FLAGS := -ldflags "-X $(GO_PACKAGE)/pkg/version.versionFromGit=$(shell git describe --long --tags --abbrev=7 --match 'v[0-9]*')"

# Include the library makefile
include $(addprefix ./vendor/github.com/openshift/build-machinery-go/make/, \
	golang.mk \
	targets/openshift/bindata.mk \
	targets/openshift/deps-gomod.mk \
	targets/openshift/images.mk \
	targets/openshift/operator/profile-manifests.mk \
)

IMAGE_REGISTRY?=registry.svc.ci.openshift.org

# This will call a macro called "build-image" which will generate image specific targets based on the parameters:
# $0 - macro name
# $1 - target name
# $2 - image ref
# $3 - Dockerfile path
# $4 - context directory for image build
# It will generate target "image-$(1)" for building the image and binding it as a prerequisite to target "images".
$(call build-image,ocp-service-ca-operator,$(IMAGE_REGISTRY)/ocp/4.3:service-ca-operator,./Dockerfile.rhel7,.)

# This will call a macro called "add-bindata" which will generate bindata specific targets based on the parameters:
# $0 - macro name
# $1 - target suffix
# $2 - input dirs
# $3 - prefix
# $4 - pkg
# $5 - output
# It will generate targets {update,verify}-bindata-$(1) logically grouping them in unsuffixed versions of these targets
# and also hooked into {update,verify}-generated for broader integration.
$(call add-bindata,v4.0.0,./bindata/v4.0.0/...,bindata,v4_00_assets,pkg/operator/v4_00_assets/bindata.go)

# include targets for profile manifest patches
# $0 - macro name
# $1 - target name
# $2 - profile patches directory
# $3 - manifests directory
$(call add-profile-manifests,manifests,./profile-patches,./manifests)

$(call verify-golang-versions,Dockerfile.rhel7)

# -------------------------------------------------------------------
# OpenShift Tests Extension (Service CA Operator)
# -------------------------------------------------------------------
.PHONY: tests-ext-build
tests-ext-build:
	$(MAKE) -C test/tests-extension build

.PHONY: tests-ext-update
tests-ext-update:
	$(MAKE) -C test/tests-extension build-update

.PHONY: tests-ext-clean
tests-ext-clean:
	$(MAKE) -C test/tests-extension clean

.PHONY: run-suite
run-suite:
	$(MAKE) -C test/tests-extension run-suite SUITE=$(SUITE) ARTIFACT_DIR=$(ARTIFACT_DIR)

clean: tests-ext-clean
	$(RM) ./service-ca-operator
.PHONY: clean

GO_TEST_PACKAGES :=./pkg/... ./cmd/...

.PHONY: test-e2e
test-e2e: GO_TEST_PACKAGES :=./test/e2e/...
test-e2e: GO_TEST_FLAGS += -v
test-e2e: GO_TEST_FLAGS += -timeout 1h
test-e2e: GO_TEST_FLAGS += -count 1
test-e2e: test-unit
