package cabundleinjector

import (
	"bytes"
	"context"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiextclientv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	apiextinformer "k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions"
	apiextlister "k8s.io/apiextensions-apiserver/pkg/client/listers/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type crdCABundleInjector struct {
	client   apiextclientv1.CustomResourceDefinitionInterface
	lister   apiextlister.CustomResourceDefinitionLister
	caBundle []byte
}

func newCRDInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	client := apiextclient.NewForConfigOrDie(config.config)
	informers := apiextinformer.NewSharedInformerFactory(client, config.defaultResync)
	informer := informers.Apiextensions().V1().CustomResourceDefinitions()
	syncer := &crdCABundleInjector{
		client:   client.ApiextensionsV1().CustomResourceDefinitions(),
		lister:   informer.Lister(),
		caBundle: config.caBundle,
	}
	return controllerConfig{
		name:     "CRDCABundleInjector",
		sync:     syncer.Sync,
		informer: informer.Informer(),
		startInformers: func(stopChan <-chan struct{}) {
			informers.Start(stopChan)
		},
		annotationsChecker: annotationsChecker(
			api.InjectCABundleAnnotationName,
		),
	}
}

func (bi *crdCABundleInjector) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	crd, err := bi.lister.Get(syncCtx.QueueKey())
	if apierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

	if crd.Spec.Conversion == nil {
		klog.Warningf("customresourcedefinition %s is annotated for ca bundle injection but spec.conversion is not specified", crd.Name)
		return nil
	}
	if crd.Spec.Conversion.Strategy != apiext.WebhookConverter {
		klog.Warningf("customresourcedefinition %s is annotated for ca bundle injection but does not use strategy %q", crd.Name, apiext.WebhookConverter)
		return nil
	}
	if bytes.Equal(crd.Spec.Conversion.Webhook.ClientConfig.CABundle, bi.caBundle) {
		// up-to-date
		return nil
	}

	klog.Infof("updating customresourcedefinition %s conversion webhook config with the service signing CA bundle", crd.Name)

	// make a copy to avoid mutating cache state
	crdCopy := crd.DeepCopy()
	crdCopy.Spec.Conversion.Webhook.ClientConfig.CABundle = bi.caBundle
	_, err = bi.client.Update(ctx, crdCopy, metav1.UpdateOptions{})
	return err
}
