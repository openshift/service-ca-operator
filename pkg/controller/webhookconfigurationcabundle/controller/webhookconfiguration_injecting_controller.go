package controller

import (
	"fmt"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionregistrationinformers "k8s.io/client-go/informers/admissionregistration/v1beta1"
	admissionregistrationclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1beta1"
	listers "k8s.io/client-go/listers/admissionregistration/v1beta1"
	"k8s.io/klog"

	"github.com/openshift/service-ca-operator/pkg/boilerplate/controller"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type webhookConfigurationCABundleInjetionController struct {
	caBundle                             []byte
	mutatingWebhookConfigurationClient   admissionregistrationclient.MutatingWebhookConfigurationsGetter
	mutatingWebhookConfigurationLister   listers.MutatingWebhookConfigurationLister
	validatingWebhookConfigurationClient admissionregistrationclient.ValidatingWebhookConfigurationsGetter
	validatingWebhookConfigurationLister listers.ValidatingWebhookConfigurationLister
}

func NewWebhookConfigurationCABundleInjectionController(mutatingWebhookConfigurationInformer admissionregistrationinformers.MutatingWebhookConfigurationInformer,
	validatingWebhookConfigurationInformer admissionregistrationinformers.ValidatingWebhookConfigurationInformer,
	client admissionregistrationclient.AdmissionregistrationV1beta1Interface,
	caBundle []byte) controller.Runner {
	ic := &webhookConfigurationCABundleInjetionController{
		caBundle:                             caBundle,
		mutatingWebhookConfigurationClient:   client.(admissionregistrationclient.MutatingWebhookConfigurationsGetter),
		mutatingWebhookConfigurationLister:   mutatingWebhookConfigurationInformer.Lister(),
		validatingWebhookConfigurationClient: client.(admissionregistrationclient.ValidatingWebhookConfigurationsGetter),
		validatingWebhookConfigurationLister: validatingWebhookConfigurationInformer.Lister(),
	}
	filter := controller.FilterFuncs{
		AddFunc:    api.HasInjectCABundleAnnotation,
		UpdateFunc: api.HasInjectCABundleAnnotationUpdate,
	}

	return controller.New("WebhookConfigurationCABundleInjectionController", ic,
		controller.WithInformer(mutatingWebhookConfigurationInformer, filter),
		controller.WithInformer(validatingWebhookConfigurationInformer, filter),
	)
}

func (ic *webhookConfigurationCABundleInjetionController) Key(_, name string) (metav1.Object, error) {
	obj, err := ic.mutatingWebhookConfigurationLister.Get(name)
	if errors.IsNotFound(err) {
		return ic.validatingWebhookConfigurationLister.Get(name)
	}
	return obj, err
}

func (ic *webhookConfigurationCABundleInjetionController) Sync(obj metav1.Object) error {
	// check if we need to do anything
	if !api.HasInjectCABundleAnnotation(obj) {
		return nil
	}

	switch webhookConfiguration := obj.(type) {
	case *admissionregistrationv1beta1.MutatingWebhookConfiguration:
		return ic.ensureMutatingWebhookConfigurationInjection(webhookConfiguration)
	case *admissionregistrationv1beta1.ValidatingWebhookConfiguration:
		return ic.ensureValidatingWebhookConfigurationInjection(webhookConfiguration)
	default:
		return fmt.Errorf("unrecognized webhookconfiguration: %T", webhookConfiguration)
	}
}

func (ic *webhookConfigurationCABundleInjetionController) ensureMutatingWebhookConfigurationInjection(webhookConfiguration *admissionregistrationv1beta1.MutatingWebhookConfiguration) error {
	// make a copy to avoid mutating cache state
	webhookConfigurationCopy := webhookConfiguration.DeepCopy()
	for i := range webhookConfigurationCopy.Webhooks {
		webhookConfigurationCopy.Webhooks[i].ClientConfig.CABundle = ic.caBundle
	}
	klog.V(4).Infof("updating mutatingwebhookconfiguration %s with CA", webhookConfigurationCopy.GetName())
	_, err := ic.mutatingWebhookConfigurationClient.MutatingWebhookConfigurations().Update(webhookConfigurationCopy)
	return err
}

func (ic *webhookConfigurationCABundleInjetionController) ensureValidatingWebhookConfigurationInjection(webhookConfiguration *admissionregistrationv1beta1.ValidatingWebhookConfiguration) error {
	// make a copy to avoid mutating cache state
	webhookConfigurationCopy := webhookConfiguration.DeepCopy()
	for i := range webhookConfigurationCopy.Webhooks {
		webhookConfigurationCopy.Webhooks[i].ClientConfig.CABundle = ic.caBundle
	}
	klog.V(4).Infof("updating validatingwebhookconfiguration %s with CA", webhookConfigurationCopy.GetName())
	_, err := ic.validatingWebhookConfigurationClient.ValidatingWebhookConfigurations().Update(webhookConfigurationCopy)
	return err
}
