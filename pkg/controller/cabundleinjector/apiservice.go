package cabundleinjector

import (
	"bytes"
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	apiserviceclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	apiserviceclientv1 "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"
	apiserviceinformer "k8s.io/kube-aggregator/pkg/client/informers/externalversions"
	apiservicelister "k8s.io/kube-aggregator/pkg/client/listers/apiregistration/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
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

	syncer := &apiServiceCABundleInjector{
		client:   client.ApiregistrationV1().APIServices(),
		lister:   informer.Lister(),
		caBundle: config.caBundle,
	}

	return controllerConfig{
		name:     "APIServiceCABundleInjector",
		sync:     syncer.Sync,
		informer: informer.Informer(),
		startInformers: func(stopChan <-chan struct{}) {
			informers.Start(stopChan)
		},
		annotationsChecker: annotationsChecker(
			api.InjectCABundleAnnotationName,
			api.AlphaInjectCABundleAnnotationName,
		),
	}
}

func (bi *apiServiceCABundleInjector) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	apiService, err := bi.lister.Get(syncCtx.QueueKey())
	if apierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

	if bytes.Equal(apiService.Spec.CABundle, bi.caBundle) {
		return nil
	}

	klog.Infof("updating apiservice %s with the service signing CA bundle", apiService.Name)

	// avoid mutating our cache
	apiServiceCopy := apiService.DeepCopy()
	apiServiceCopy.Spec.CABundle = bi.caBundle
	_, err = bi.client.Update(context.TODO(), apiServiceCopy, v1.UpdateOptions{})
	return err
}
