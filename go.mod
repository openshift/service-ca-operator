module github.com/openshift/service-ca-operator

go 1.14

require (
	github.com/go-bindata/go-bindata v3.1.2+incompatible
	github.com/go-logr/logr v0.3.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.1.1
	github.com/openshift/api v0.0.0-20201117184740-859beeffd973
	github.com/openshift/build-machinery-go v0.0.0-20200917070002-f171684f77ab
	github.com/openshift/client-go v0.0.0-20200827190008-3062137373b5
	github.com/openshift/library-go v0.0.0-20200921120329-c803a7b7bb2c
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/common v0.10.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b // indirect
	golang.org/x/text v0.3.4 // indirect
	k8s.io/api v0.19.4
	k8s.io/apiextensions-apiserver v0.19.2
	k8s.io/apimachinery v0.19.4
	k8s.io/client-go v0.19.2
	k8s.io/component-base v0.19.2
	k8s.io/klog/v2 v2.4.0
	k8s.io/kube-aggregator v0.19.2
	k8s.io/utils v0.0.0-20200729134348-d5654de09c73
	sigs.k8s.io/structured-merge-diff/v4 v4.0.2 // indirect
)

replace vbom.ml/util => github.com/fvbommel/util v0.0.0-20180919145318-efcd4e0f9787
