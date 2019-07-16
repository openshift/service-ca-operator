#!/bin/bash

CRD_SCHEMA_GEN_VERSION="v1.0.0"
CRD_SCHEMA_GEN_GOPATH=$(mktemp -d)
git clone -b ${CRD_SCHEMA_GEN_VERSION} --single-branch --depth 1 https://github.com/openshift/crd-schema-gen.git ${CRD_SCHEMA_GEN_GOPATH}/src/github.com/openshift/crd-schema-gen
GOPATH=${CRD_SCHEMA_GEN_GOPATH} \
    GOBIN=${CRD_SCHEMA_GEN_GOPATH}/bin \
    go install ${CRD_SCHEMA_GEN_GOPATH}/src/github.com/openshift/crd-schema-gen/cmd/crd-schema-gen
${CRD_SCHEMA_GEN_GOPATH}/bin/crd-schema-gen --apis-dir vendor/github.com/openshift/api/operator/v1 --verify-only
