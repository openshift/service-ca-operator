package controller

import (
	"bytes"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	webhookinformer "k8s.io/client-go/informers/admissionregistration/v1beta1"
	webhookclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1beta1"
	webhooklister "k8s.io/client-go/listers/admissionregistration/v1beta1"
	"monis.app/go/openshift/controller"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type serviceServingCertUpdateController struct {
	webhookClient webhookclient.ValidatingWebhookConfigurationsGetter
	webhookLister webhooklister.ValidatingWebhookConfigurationLister

	caBundle []byte
}

func NewWebhookCABundleInjector(webhookInformer webhookinformer.ValidatingWebhookConfigurationInformer, webhookClient webhookclient.ValidatingWebhookConfigurationsGetter, caBundle []byte) controller.Runner {
	sc := &serviceServingCertUpdateController{
		webhookClient: webhookClient,
		webhookLister: webhookInformer.Lister(),
		caBundle:      caBundle,
	}

	return controller.New("WebhookCABundleInjector", sc,
		controller.WithInformer(webhookInformer, controller.FilterFuncs{
			AddFunc:    api.HasInjectCABundleAnnotation,
			UpdateFunc: api.HasInjectCABundleAnnotationUpdate,
		}),
	)
}

func (c *serviceServingCertUpdateController) Key(namespace, name string) (v1.Object, error) {
	return c.webhookLister.Get(name)
}

func (c *serviceServingCertUpdateController) Sync(obj v1.Object) error {
	webhook := obj.(*admissionregistrationv1beta1.ValidatingWebhookConfiguration)

	// check if we need to do anything
	if !api.HasInjectCABundleAnnotation(webhook) {
		return nil
	}

	webhookCopy := webhook.DeepCopy()
	for index, webhookConfig := range webhook.Webhooks {
		// TODO(jaosorior): Make base64
		if bytes.Equal(webhookConfig.ClientConfig.CABundle, c.caBundle) {
			continue
		}

		// avoid mutating our cache
		webhookCopy.Webhooks[index].ClientConfig.CABundle = c.caBundle
	}
	_, err := c.webhookClient.ValidatingWebhookConfigurations().Update(webhookCopy)
	return err
}
