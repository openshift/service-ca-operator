module github.com/openshift/service-ca-operator

go 1.14

require (
	github.com/go-bindata/go-bindata v3.1.2+incompatible
	github.com/google/uuid v1.1.1
	github.com/openshift/api v0.0.0-20200803131051-87466835fcc0
	github.com/openshift/build-machinery-go v0.0.0-20200731024703-cd7e6e844b55
	github.com/openshift/client-go v0.0.0-20200729195840-c2b1adc6bed6
	github.com/openshift/library-go v0.0.0-20200807122248-f5cb4d19a4fe
	github.com/openshift/operator-boilerplate-legacy v0.0.0-20200817104504-304122b697f3
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/common v0.10.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	k8s.io/api v0.19.0-rc.2
	k8s.io/apiextensions-apiserver v0.19.0-rc.2
	k8s.io/apimachinery v0.19.0-rc.2
	k8s.io/client-go v0.19.0-rc.2
	k8s.io/component-base v0.19.0-rc.2
	k8s.io/klog/v2 v2.3.0
	k8s.io/kube-aggregator v0.19.0-rc.2
)
