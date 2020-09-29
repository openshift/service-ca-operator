module github.com/openshift/service-ca-operator

go 1.14

require (
	github.com/go-bindata/go-bindata v3.1.2+incompatible
	github.com/google/uuid v1.1.1
	github.com/openshift/api v0.0.0-20200929125329-c3027fc03b92
	github.com/openshift/build-machinery-go v0.0.0-20200819073603-48aa266c95f7
	github.com/openshift/client-go v0.0.0-20200827190008-3062137373b5
	github.com/openshift/library-go v0.0.0-20200918101923-1e4c94603efe
	github.com/openshift/operator-boilerplate-legacy v0.0.0-20200817104504-304122b697f3
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/common v0.10.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	k8s.io/api v0.19.2
	k8s.io/apiextensions-apiserver v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/client-go v0.19.2
	k8s.io/component-base v0.19.2
	k8s.io/klog/v2 v2.3.0
	k8s.io/kube-aggregator v0.19.2
)

replace vbom.ml/util => github.com/fvbommel/util v0.0.0-20180919145318-efcd4e0f9787
