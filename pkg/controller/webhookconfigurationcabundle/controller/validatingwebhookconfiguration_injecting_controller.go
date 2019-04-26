package controller

import (
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionregistrationinformers "k8s.io/client-go/informers/admissionregistration/v1beta1"
	admissionregistrationclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1beta1"
	listers "k8s.io/client-go/listers/admissionregistration/v1beta1"
	"k8s.io/klog"

	"github.com/openshift/service-ca-operator/pkg/boilerplate/controller"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type validatingWebhookConfigurationCABundleInjetionController struct {
	caBundle []byte
	client   admissionregistrationclient.ValidatingWebhookConfigurationsGetter
	lister   listers.ValidatingWebhookConfigurationLister
}

func NewValidatingWebhookConfigurationCABundleInjectionController(informer admissionregistrationinformers.ValidatingWebhookConfigurationInformer, client admissionregistrationclient.ValidatingWebhookConfigurationsGetter, caBundle []byte) controller.Runner {
	ic := &validatingWebhookConfigurationCABundleInjetionController{
		caBundle: caBundle,
		client:   client,
		lister:   informer.Lister(),
	}

	return controller.New("ValidatingWebhookConfigurationCABundleInjectionController", ic,
		controller.WithInformer(informer, controller.FilterFuncs{
			AddFunc:    api.HasInjectCABundleAnnotation,
			UpdateFunc: api.HasInjectCABundleAnnotationUpdate,
		}),
	)
}

func (ic *validatingWebhookConfigurationCABundleInjetionController) Key(_, name string) (metav1.Object, error) {
	return ic.lister.Get(name)
}

func (ic *validatingWebhookConfigurationCABundleInjetionController) Sync(obj metav1.Object) error {
	webhookConfiguration := obj.(*admissionregistrationv1beta1.ValidatingWebhookConfiguration)

	// check if we need to do anything
	if !api.HasInjectCABundleAnnotation(webhookConfiguration) {
		return nil
	}

	return ic.ensureInjection(webhookConfiguration)
}

func (ic *validatingWebhookConfigurationCABundleInjetionController) ensureInjection(webhookConfiguration *admissionregistrationv1beta1.ValidatingWebhookConfiguration) error {
	// make a copy to avoid mutating cache state
	webhookConfigurationCopy := webhookConfiguration.DeepCopy()
	for i := range webhookConfigurationCopy.Webhooks {
		webhookConfigurationCopy.Webhooks[i].ClientConfig.CABundle = ic.caBundle
	}
	klog.V(4).Infof("updating validatingwebhookconfiguration %s with CA", webhookConfigurationCopy.GetName())
	_, err := ic.client.ValidatingWebhookConfigurations().Update(webhookConfigurationCopy)
	return err
}
