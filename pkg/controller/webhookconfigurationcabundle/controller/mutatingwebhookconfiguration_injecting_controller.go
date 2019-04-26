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

type mutatingWebhookConfigurationCABundleInjetionController struct {
	caBundle []byte
	client   admissionregistrationclient.MutatingWebhookConfigurationsGetter
	lister   listers.MutatingWebhookConfigurationLister
}

func NewMutatingWebhookConfigurationCABundleInjectionController(informer admissionregistrationinformers.MutatingWebhookConfigurationInformer, client admissionregistrationclient.MutatingWebhookConfigurationsGetter, caBundle []byte) controller.Runner {
	ic := &mutatingWebhookConfigurationCABundleInjetionController{
		caBundle: caBundle,
		client:   client,
		lister:   informer.Lister(),
	}

	return controller.New("MutatingWebhookConfigurationCABundleInjectionController", ic,
		controller.WithInformer(informer, controller.FilterFuncs{
			AddFunc:    api.HasInjectCABundleAnnotation,
			UpdateFunc: api.HasInjectCABundleAnnotationUpdate,
		}),
	)
}

func (ic *mutatingWebhookConfigurationCABundleInjetionController) Key(_, name string) (metav1.Object, error) {
	return ic.lister.Get(name)
}

func (ic *mutatingWebhookConfigurationCABundleInjetionController) Sync(obj metav1.Object) error {
	webhookConfiguration := obj.(*admissionregistrationv1beta1.MutatingWebhookConfiguration)

	// check if we need to do anything
	if !api.HasInjectCABundleAnnotation(webhookConfiguration) {
		return nil
	}

	return ic.ensureInjection(webhookConfiguration)
}

func (ic *mutatingWebhookConfigurationCABundleInjetionController) ensureInjection(webhookConfiguration *admissionregistrationv1beta1.MutatingWebhookConfiguration) error {
	// make a copy to avoid mutating cache state
	webhookConfigurationCopy := webhookConfiguration.DeepCopy()
	for i := range webhookConfigurationCopy.Webhooks {
		webhookConfigurationCopy.Webhooks[i].ClientConfig.CABundle = ic.caBundle
	}
	klog.V(4).Infof("updating mutatingwebhookconfiguration %s with CA", webhookConfigurationCopy.GetName())
	_, err := ic.client.MutatingWebhookConfigurations().Update(webhookConfigurationCopy)
	return err
}
