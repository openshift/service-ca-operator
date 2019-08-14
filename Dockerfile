FROM registry.svc.ci.openshift.org/openshift/release:golang-1.12 AS builder
WORKDIR /go/src/github.com/openshift/service-ca-operator
COPY . .
ENV GO_PACKAGE github.com/openshift/service-ca-operator
RUN go build -ldflags "-X $GO_PACKAGE/pkg/version.versionFromGit=$(git describe --long --tags --abbrev=7 --match 'v[0-9]*')" ./cmd/service-ca-operator

FROM registry.svc.ci.openshift.org/openshift/origin-v4.0:base
COPY --from=builder /go/src/github.com/openshift/service-ca-operator/service-ca-operator /usr/bin/
COPY manifests /manifests
ENTRYPOINT ["/usr/bin/service-ca-operator"]
LABEL io.openshift.release.operator=true
