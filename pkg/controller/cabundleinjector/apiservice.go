package cabundleinjector

import (
	"bytes"
	"context"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiserviceclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	apiserviceclientv1 "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"
	apiserviceinformer "k8s.io/kube-aggregator/pkg/client/informers/externalversions"
	apiservicelister "k8s.io/kube-aggregator/pkg/client/listers/apiregistration/v1"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type apiServiceCABundleInjector struct {
	client   apiserviceclientv1.APIServiceInterface
	lister   apiservicelister.APIServiceLister
	caBundle []byte
}

func newAPIServiceInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	client := apiserviceclient.NewForConfigOrDie(config.config)
	informers := apiserviceinformer.NewSharedInformerFactory(client, config.defaultResync)
	informer := informers.Apiregistration().V1().APIServices()

	keySyncer := &apiServiceCABundleInjector{
		client:   client.ApiregistrationV1().APIServices(),
		lister:   informer.Lister(),
		caBundle: config.caBundle,
	}

	return controllerConfig{
		name:           "APIServiceCABundleInjector",
		keySyncer:      keySyncer,
		informerGetter: informer,
		startInformers: func(stopChan <-chan struct{}) {
			informers.Start(stopChan)
		},
		supportedAnnotations: []string{
			api.InjectCABundleAnnotationName,
			api.AlphaInjectCABundleAnnotationName,
		},
	}
}

func (bi *apiServiceCABundleInjector) Key(namespace, name string) (v1.Object, error) {
	return bi.lister.Get(name)
}

func (bi *apiServiceCABundleInjector) Sync(obj v1.Object) error {
	apiService := obj.(*apiregistrationv1.APIService)
	if bytes.Equal(apiService.Spec.CABundle, bi.caBundle) {
		return nil
	}

	klog.Infof("updating apiservice %s with the service signing CA bundle", apiService.Name)

	// avoid mutating our cache
	apiServiceCopy := apiService.DeepCopy()
	apiServiceCopy.Spec.CABundle = bi.caBundle
	_, err := bi.client.Update(context.TODO(), apiServiceCopy, v1.UpdateOptions{})
	return err
}
