package util

import (
	"bytes"
	"context"
	"fmt"
	"time"

	admissionreg "k8s.io/api/admissionregistration/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	admissionregclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiserviceclientv1 "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"
)

// PollForAPIService returns the specified APIService if its ca bundle matches the provided value
func PollForAPIService(client apiserviceclientv1.APIServiceInterface, name string, expectedCABundle []byte) (*apiregv1.APIService, error) {
	var apiService *apiregv1.APIService
	err := wait.PollImmediate(5*time.Second, 60*time.Second, func() (bool, error) {
		as, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		actualCABundle := as.Spec.CABundle
		if len(actualCABundle) == 0 {
			return false, fmt.Errorf("ca bundle not injected")
		}
		if !bytes.Equal(actualCABundle, expectedCABundle) {
			return false, fmt.Errorf("ca bundle does not match the expected value")
		}
		apiService = as
		return true, nil
	})
	return apiService, err
}

// PollForCRD returns the specified CustomResourceDefinition if the ca bundle for its conversion webhook config matches the provided value
func PollForCRD(client apiextclient.CustomResourceDefinitionInterface, name string, expectedCABundle []byte) (*apiext.CustomResourceDefinition, error) {
	var crd *apiext.CustomResourceDefinition
	err := wait.PollImmediate(5*time.Second, 60*time.Second, func() (bool, error) {
		c, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if c.Spec.Conversion == nil || c.Spec.Conversion.Webhook == nil || c.Spec.Conversion.Webhook.ClientConfig == nil {
			return false, fmt.Errorf("spec.conversion.webhook.webhook.clientConfig not set")
		}
		actualCABundle := c.Spec.Conversion.Webhook.ClientConfig.CABundle
		if len(actualCABundle) == 0 {
			return false, fmt.Errorf("ca bundle not injected")
		}
		if !bytes.Equal(actualCABundle, expectedCABundle) {
			return false, fmt.Errorf("ca bundle does not match the expected value")
		}
		crd = c
		return true, nil
	})
	return crd, err
}

// PollForMutatingWebhookConfiguration returns the specified MutatingWebhookConfiguration if the ca bundle for all its webhooks match the provided value
func PollForMutatingWebhookConfiguration(client admissionregclient.MutatingWebhookConfigurationInterface, name string, expectedCABundle []byte) (*admissionreg.MutatingWebhookConfiguration, error) {
	var webhookConfig *admissionreg.MutatingWebhookConfiguration
	err := wait.PollImmediate(5*time.Second, 60*time.Second, func() (bool, error) {
		wc, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		for _, webhook := range wc.Webhooks {
			err := CheckWebhookCABundle(webhook.Name, expectedCABundle, webhook.ClientConfig.CABundle)
			if err != nil {
				return false, err
			}
		}
		webhookConfig = wc
		return true, nil
	})
	return webhookConfig, err
}

// PollForValidatingWebhookConfiguration returns the specified ValidatingWebhookConfiguration if the ca bundle for all its webhooks match the provided value
func PollForValidatingWebhookConfiguration(client admissionregclient.ValidatingWebhookConfigurationInterface, name string, expectedCABundle []byte) (*admissionreg.ValidatingWebhookConfiguration, error) {
	var webhookConfig *admissionreg.ValidatingWebhookConfiguration
	err := wait.PollImmediate(5*time.Second, 60*time.Second, func() (bool, error) {
		wc, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		for _, webhook := range wc.Webhooks {
			err := CheckWebhookCABundle(webhook.Name, expectedCABundle, webhook.ClientConfig.CABundle)
			if err != nil {
				return false, err
			}
		}
		webhookConfig = wc
		return true, nil
	})
	return webhookConfig, err
}

// CheckWebhookCABundle checks that the ca bundle for the named webhook matches the expected value
func CheckWebhookCABundle(webhookName string, expectedCABundle, actualCABundle []byte) error {
	if len(actualCABundle) == 0 {
		return fmt.Errorf("ca bundle not injected for webhook %q", webhookName)
	}
	if !bytes.Equal(actualCABundle, expectedCABundle) {
		return fmt.Errorf("ca bundle does not match the expected value for webhook %q", webhookName)
	}
	return nil
}

// CreateAPIService creates an APIService with CA bundle injection annotation
func CreateAPIService(client apiserviceclientv1.APIServiceInterface, randomGroup, version string) (*apiregv1.APIService, error) {
	obj := &apiregv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s.%s", version, randomGroup),
		},
		Spec: apiregv1.APIServiceSpec{
			Group:                randomGroup,
			Version:              version,
			GroupPriorityMinimum: 1,
			VersionPriority:      1,
			Service: &apiregv1.ServiceReference{
				Namespace: "foo",
				Name:      "foo",
			},
		},
	}
	SetInjectionAnnotation(&obj.ObjectMeta)
	return client.Create(context.TODO(), obj, metav1.CreateOptions{})
}

// CreateCRD creates a CustomResourceDefinition with webhook conversion and CA bundle injection
func CreateCRD(client apiextclient.CustomResourceDefinitionInterface, randomGroup, pluralName, version string) (*apiext.CustomResourceDefinition, error) {
	obj := &apiext.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s.%s", pluralName, randomGroup),
		},
		Spec: apiext.CustomResourceDefinitionSpec{
			Group: randomGroup,
			Scope: apiext.ClusterScoped,
			Names: apiext.CustomResourceDefinitionNames{
				Plural: pluralName,
				Kind:   "CABundleInjectionTarget",
			},
			Conversion: &apiext.CustomResourceConversion{
				Strategy: apiext.WebhookConverter,
				Webhook: &apiext.WebhookConversion{
					ClientConfig: &apiext.WebhookClientConfig{
						Service: &apiext.ServiceReference{
							Namespace: "foo",
							Name:      "foo",
						},
					},
					ConversionReviewVersions: []string{version},
				},
			},
			Versions: []apiext.CustomResourceDefinitionVersion{
				{
					Name:    version,
					Storage: true,
					Schema: &apiext.CustomResourceValidation{
						OpenAPIV3Schema: &apiext.JSONSchemaProps{
							Type: "object",
						},
					},
				},
			},
		},
	}
	SetInjectionAnnotation(&obj.ObjectMeta)
	return client.Create(context.TODO(), obj, metav1.CreateOptions{})
}

// CreateMutatingWebhookConfiguration creates a MutatingWebhookConfiguration with CA bundle injection
func CreateMutatingWebhookConfiguration(client admissionregclient.MutatingWebhookConfigurationInterface) (*admissionreg.MutatingWebhookConfiguration, error) {
	sideEffectNone := admissionreg.SideEffectClassNone
	obj := &admissionreg.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "e2e-",
		},
		Webhooks: []admissionreg.MutatingWebhook{
			{
				Name:                    "e2e-1.example.com",
				ClientConfig:            getWebhookClientConfig(),
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1beta1"},
			},
			{
				Name:                    "e2e-2.example.com",
				ClientConfig:            getWebhookClientConfig(),
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1beta1"},
			},
		},
	}
	SetInjectionAnnotation(&obj.ObjectMeta)
	return client.Create(context.TODO(), obj, metav1.CreateOptions{})
}

// CreateValidatingWebhookConfiguration creates a ValidatingWebhookConfiguration with CA bundle injection
func CreateValidatingWebhookConfiguration(client admissionregclient.ValidatingWebhookConfigurationInterface) (*admissionreg.ValidatingWebhookConfiguration, error) {
	sideEffectNone := admissionreg.SideEffectClassNone
	obj := &admissionreg.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "e2e-",
		},
		Webhooks: []admissionreg.ValidatingWebhook{
			{
				Name:                    "e2e-1.example.com",
				ClientConfig:            getWebhookClientConfig(),
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1beta1"},
			},
			{
				Name:                    "e2e-2.example.com",
				ClientConfig:            getWebhookClientConfig(),
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1beta1"},
			},
		},
	}
	SetInjectionAnnotation(&obj.ObjectMeta)
	return client.Create(context.TODO(), obj, metav1.CreateOptions{})
}

func getWebhookClientConfig() admissionreg.WebhookClientConfig {
	return admissionreg.WebhookClientConfig{
		Service: &admissionreg.ServiceReference{
			Namespace: "foo",
			Name:      "foo",
		},
	}
}
