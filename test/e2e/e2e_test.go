package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	admissionreg "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	admissionregclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiserviceclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	apiserviceclientv1 "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"
	"k8s.io/utils/clock"

	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/operator"
	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"
	"github.com/openshift/service-ca-operator/test/util"
)

const (
	serviceCAOperatorNamespace   = operatorclient.OperatorNamespace
	serviceCAOperatorPodPrefix   = operatorclient.OperatorName
	serviceCAControllerNamespace = operatorclient.TargetNamespace
	serviceCAPodPrefix           = api.ServiceCADeploymentName
	signingKeySecretName         = api.ServiceCASecretName

	// A label used to attach StatefulSet pods to a headless service created by
	// createServingCertAnnotatedService
	owningHeadlessServiceLabelName = "owning-headless-service"

	signingCertificateLifetime = 790 * 24 * time.Hour
)

// checkComponents verifies that the components of the operator are running.
func checkComponents(t *testing.T, client *kubernetes.Clientset) {
	componentConfigs := []struct {
		namespace string
		podPrefix string
	}{
		{serviceCAOperatorNamespace, serviceCAOperatorPodPrefix},
		{serviceCAControllerNamespace, serviceCAPodPrefix},
	}
	for _, cfg := range componentConfigs {
		pods, err := client.CoreV1().Pods(cfg.namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			t.Fatalf("Failed to list pods in namespace %q: %v", cfg.namespace, err)
		}
		podFound := false
		for _, pod := range pods.Items {
			if strings.HasPrefix(pod.GetName(), cfg.podPrefix) {
				podFound = true
				break
			}
		}
		if !podFound {
			t.Fatalf("No pods with prefix %q found running in namespace %q", cfg.podPrefix, cfg.namespace)
		}
	}
}

func editServingSecretData(t *testing.T, client *kubernetes.Clientset, secretName, namespace, keyName string) error {
	sss, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	scopy := sss.DeepCopy()
	scopy.Data[keyName] = []byte("blah")
	_, err = client.CoreV1().Secrets(namespace).Update(context.TODO(), scopy, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return pollForSecretChange(t, client, scopy, keyName)
}

func pollForCABundleInjectionConfigMapWithReturn(client *kubernetes.Clientset, configMapName, namespace string) (*v1.ConfigMap, error) {
	var configmap *v1.ConfigMap
	err := wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		configmap = cm
		return true, nil
	})
	return configmap, err
}

func pollForSecretChange(t *testing.T, client *kubernetes.Clientset, secret *v1.Secret, keysToChange ...string) error {
	return wait.PollImmediate(pollInterval, rotationPollTimeout, func() (bool, error) {
		s, err := client.CoreV1().Secrets(secret.Namespace).Get(context.TODO(), secret.Name, metav1.GetOptions{})
		if err != nil {
			tlogf(t, "failed to get secret: %v", err)
			return false, nil
		}
		for _, key := range keysToChange {
			if bytes.Equal(s.Data[key], secret.Data[key]) {
				return false, nil
			}
		}
		return true, nil
	})
}

type triggerRotationFunc func(*testing.T, *kubernetes.Clientset, *rest.Config)

func checkCARotation(t *testing.T, client *kubernetes.Clientset, config *rest.Config, triggerRotation triggerRotationFunc) {
	ns, cleanup, err := createTestNamespace(t, client, "test-"+randSeq(5))
	if err != nil {
		t.Fatalf("could not create test namespace: %v", err)
	}
	defer cleanup()

	// Prompt the creation of service cert secrets
	testServiceName := "test-service-" + randSeq(5)
	testSecretName := "test-secret-" + randSeq(5)
	testHeadlessServiceName := "test-headless-service-" + randSeq(5)
	testHeadlessSecretName := "test-headless-secret-" + randSeq(5)

	err = createServingCertAnnotatedService(client, testSecretName, testServiceName, ns.Name, false)
	if err != nil {
		t.Fatalf("error creating annotated service: %v", err)
	}
	if err = createServingCertAnnotatedService(client, testHeadlessSecretName, testHeadlessServiceName, ns.Name, true); err != nil {
		t.Fatalf("error creating annotated headless service: %v", err)
	}

	// Prompt the injection of the ca bundle into a configmap
	testConfigMapName := "test-configmap-" + randSeq(5)

	err = createAnnotatedCABundleInjectionConfigMap(client, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error creating annotated configmap: %v", err)
	}

	// Retrieve the pre-rotation service cert
	oldCertPEM, oldKeyPEM, err := pollForUpdatedServingCert(t, client, ns.Name, testSecretName, rotationPollTimeout, nil, nil)
	if err != nil {
		t.Fatalf("error retrieving service cert: %v", err)
	}
	oldHeadlessCertPEM, oldHeadlessKeyPEM, err := pollForUpdatedServingCert(t, client, ns.Name, testHeadlessSecretName, rotationPollTimeout, nil, nil)
	if err != nil {
		t.Fatalf("error retrieving headless service cert: %v", err)
	}

	// Retrieve the pre-rotation ca bundle
	oldBundlePEM, err := pollForInjectedCABundle(t, client, ns.Name, testConfigMapName, rotationPollTimeout, nil)
	if err != nil {
		t.Fatalf("error retrieving ca bundle: %v", err)
	}

	// Prompt CA rotation
	triggerRotation(t, client, config)

	// Retrieve the post-rotation service cert
	newCertPEM, newKeyPEM, err := pollForUpdatedServingCert(t, client, ns.Name, testSecretName, rotationTimeout, oldCertPEM, oldKeyPEM)
	if err != nil {
		t.Fatalf("error retrieving service cert: %v", err)
	}
	newHeadlessCertPEM, newHeadlessKeyPEM, err := pollForUpdatedServingCert(t, client, ns.Name, testHeadlessSecretName, rotationTimeout, oldHeadlessCertPEM, oldHeadlessKeyPEM)
	if err != nil {
		t.Fatalf("error retrieving headless service cert: %v", err)
	}

	// Retrieve the post-rotation ca bundle
	newBundlePEM, err := pollForInjectedCABundle(t, client, ns.Name, testConfigMapName, rotationTimeout, oldBundlePEM)
	if err != nil {
		t.Fatalf("error retrieving ca bundle: %v", err)
	}

	// Determine the dns name valid for the serving cert
	certs, err := util.PemToCerts(newCertPEM)
	if err != nil {
		t.Fatalf("error decoding pem to certs: %v", err)
	}
	dnsName := certs[0].Subject.CommonName

	util.CheckRotation(t, dnsName, oldCertPEM, oldKeyPEM, oldBundlePEM, newCertPEM, newKeyPEM, newBundlePEM)

	for i := 0; i < 3; i++ { // 3 is an arbitrary number of hostnames to try
		dnsName := fmt.Sprintf("some-statefulset-%d.%s.%s.svc", i, testHeadlessServiceName, ns.Name)
		util.CheckRotation(t, dnsName, oldHeadlessCertPEM, oldHeadlessKeyPEM, oldBundlePEM, newHeadlessCertPEM, newHeadlessKeyPEM, newBundlePEM)
	}
}

// triggerTimeBasedRotation replaces the current CA cert with one that
// is not valid for the minimum required duration and waits for the CA
// to be rotated.
func triggerTimeBasedRotation(t *testing.T, client *kubernetes.Clientset, config *rest.Config) {
	// A rotation-prompting CA cert needs to be a renewed instance
	// (i.e. share the same public and private keys) of the current
	// cert to ensure that trust will be maintained for unrefreshed
	// clients and servers.

	// Retrieve current CA
	secret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error retrieving signing key secret: %v", err)
	}
	// Store the old PEMs for comparison
	oldCACertPEM := secret.Data[v1.TLSCertKey]
	oldCAKeyPEM := secret.Data[v1.TLSPrivateKeyKey]

	currentCACerts, err := util.PemToCerts(secret.Data[v1.TLSCertKey])
	if err != nil {
		t.Fatalf("error unmarshaling %q: %v", v1.TLSCertKey, err)
	}
	currentCAKey, err := util.PemToKey(secret.Data[v1.TLSPrivateKeyKey])
	if err != nil {
		t.Fatalf("error unmarshalling %q: %v", v1.TLSPrivateKeyKey, err)
	}
	currentCAConfig := &crypto.TLSCertificateConfig{
		Certs: currentCACerts,
		Key:   currentCAKey,
	}

	// Trigger rotation by renewing the current ca with an expiry that
	// is sooner than the minimum required duration.
	renewedCAConfig, err := operator.RenewSelfSignedCertificate(currentCAConfig, 1*time.Hour, true)
	if err != nil {
		t.Fatalf("error renewing ca to half-expired form: %v", err)
	}
	renewedCACertPEM, renewedCAKeyPEM, err := renewedCAConfig.GetPEMBytes()
	if err != nil {
		t.Fatalf("error encoding renewed ca to pem: %v", err)
	}

	// Write the renewed CA
	secret = &v1.Secret{
		Type: v1.SecretTypeTLS,
		ObjectMeta: metav1.ObjectMeta{
			Name:      signingKeySecretName,
			Namespace: serviceCAControllerNamespace,
		},
		Data: map[string][]byte{
			v1.TLSCertKey:       renewedCACertPEM,
			v1.TLSPrivateKeyKey: renewedCAKeyPEM,
		},
	}
	_, _, err = resourceapply.ApplySecret(context.Background(), client.CoreV1(), events.NewInMemoryRecorder("test", clock.RealClock{}), secret)
	if err != nil {
		t.Fatalf("error updating secret with test CA: %v", err)
	}

	_ = pollForCARotation(t, client, oldCACertPEM, oldCAKeyPEM)
}

// triggerForcedRotation forces the rotation of the current CA via the
// operator config.
func triggerForcedRotation(t *testing.T, client *kubernetes.Clientset, config *rest.Config) {
	// Retrieve the cert and key PEM of the current CA to be able to
	// detect when rotation has completed.
	secret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error retrieving signing key secret: %v", err)
	}
	caCertPEM := secret.Data[v1.TLSCertKey]
	caKeyPEM := secret.Data[v1.TLSPrivateKeyKey]

	// Set a custom validity duration longer than the default to
	// validate that a custom expiry on rotation is possible.
	defaultDuration := signingCertificateLifetime
	customDuration := defaultDuration + 1*time.Hour

	// Trigger a forced rotation by updating the operator config
	// with a reason.
	forceUnsupportedServiceCAConfigRotation(t, config, secret, customDuration)

	signingSecret := pollForCARotation(t, client, caCertPEM, caKeyPEM)

	// Check that the expiry of the new CA is longer than the default
	rawCert := signingSecret.Data[v1.TLSCertKey]
	certs, err := cert.ParseCertsPEM(rawCert)
	if err != nil {
		t.Fatalf("Failed to parse signing secret cert: %v", err)
	}
	if !certs[0].NotAfter.After(time.Now().Add(defaultDuration)) {
		t.Fatalf("Custom validity duration was not used to generate the new CA")
	}
}

func forceUnsupportedServiceCAConfigRotation(t *testing.T, config *rest.Config, currentSigningKeySecret *v1.Secret, validityDuration time.Duration) {
	operatorClient, err := operatorv1client.NewForConfig(config)
	if err != nil {
		t.Fatalf("error creating operator client: %v", err)
	}
	operatorConfig, err := operatorClient.OperatorV1().ServiceCAs().Get(context.TODO(), api.OperatorConfigInstanceName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error retrieving operator config: %v", err)
	}
	var forceRotationReason string
	for i := 0; ; i++ {
		forceRotationReason = fmt.Sprintf("service-ca-e2e-force-rotation-reason-%d", i)
		if currentSigningKeySecret.Annotations[api.ForcedRotationReasonAnnotationName] != forceRotationReason {
			break
		}
	}
	rawUnsupportedServiceCAConfig, err := operator.RawUnsupportedServiceCAConfig(forceRotationReason, validityDuration)
	if err != nil {
		t.Fatalf("failed to create raw unsupported config overrides: %v", err)
	}
	operatorConfig.Spec.UnsupportedConfigOverrides.Raw = rawUnsupportedServiceCAConfig
	_, err = operatorClient.OperatorV1().ServiceCAs().Update(context.TODO(), operatorConfig, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error updating operator config: %v", err)
	}
}

// pollForCARotation polls for the signing secret to be changed in
// response to CA rotation.
func pollForCARotation(t *testing.T, client *kubernetes.Clientset, caCertPEM, caKeyPEM []byte) *v1.Secret {
	resourceID := fmt.Sprintf("Secret \"%s/%s\"", serviceCAControllerNamespace, signingKeySecretName)
	obj, err := pollForResource(t, resourceID, rotationPollTimeout, func() (kruntime.Object, error) {
		secret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		// Check if both cert and key are still the same as the old values
		if bytes.Equal(secret.Data[v1.TLSCertKey], caCertPEM) && bytes.Equal(secret.Data[v1.TLSPrivateKeyKey], caKeyPEM) {
			return nil, fmt.Errorf("cert and key have not changed yet")
		}
		return secret, nil
	})
	if err != nil {
		t.Fatalf("error waiting for CA rotation: %v", err)
	}
	return obj.(*v1.Secret)
}

// pollForCARecreation polls for the signing secret to be re-created in
// response to CA secret deletion.
func pollForCARecreation(client *kubernetes.Clientset) error {
	return wait.PollImmediate(time.Second, rotationPollTimeout, func() (bool, error) {
		_, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

// pollForUpdatedServingCert returns the cert and key PEM if it changes from
// that provided before the polling timeout.

// pollForUpdatedSecret returns the given secret if its data changes from
// that provided before the polling timeout.
func pollForUpdatedSecret(t *testing.T, client *kubernetes.Clientset, namespace, name string, timeout time.Duration, oldData map[string][]byte) (*v1.Secret, error) {
	resourceID := fmt.Sprintf("Secret \"%s/%s\"", namespace, name)
	obj, err := pollForResource(t, resourceID, timeout, func() (kruntime.Object, error) {
		secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		err = util.CheckData(oldData, secret.Data)
		if err != nil {
			return nil, err
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*v1.Secret), nil
}

// pollForInjectedCABundle returns the bytes for the injection key in
// the targeted configmap if the value of the key changes from that
// provided before the polling timeout.
func pollForInjectedCABundle(t *testing.T, client *kubernetes.Clientset, namespace, name string, timeout time.Duration, oldValue []byte) ([]byte, error) {
	return pollForUpdatedConfigMap(t, client, namespace, name, api.InjectionDataKey, timeout, oldValue)
}

// pollForSigningCABundle returns the bytes for the bundle key of the
// signing ca bundle configmap if the value is non-empty before the
// polling timeout.
func pollForSigningCABundle(t *testing.T, client *kubernetes.Clientset) ([]byte, error) {
	return pollForUpdatedConfigMap(t, client, serviceCAControllerNamespace, api.SigningCABundleConfigMapName, api.BundleDataKey, pollTimeout, nil)
}

// pollForUpdatedConfigMap returns the given configmap if its data changes from
// that provided before the polling timeout.
func pollForUpdatedConfigMap(t *testing.T, client *kubernetes.Clientset, namespace, name, key string, timeout time.Duration, oldValue []byte) ([]byte, error) {
	resourceID := fmt.Sprintf("ConfigMap \"%s/%s\"", namespace, name)
	obj, err := pollForResource(t, resourceID, timeout, func() (kruntime.Object, error) {
		configMap, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		// For rotation tests, we need to be more flexible about data size
		if len(configMap.Data) == 0 {
			return nil, fmt.Errorf("configmap has no data")
		}
		value, ok := configMap.Data[key]
		if !ok {
			return nil, fmt.Errorf("key %q is missing", key)
		}
		if oldValue != nil && value == string(oldValue) {
			return nil, fmt.Errorf("value for key %q has not changed", key)
		}
		return configMap, nil
	})
	if err != nil {
		return nil, err
	}
	configMap := obj.(*v1.ConfigMap)
	return []byte(configMap.Data[key]), nil
}

// pollForAPIService returns the specified APIService if its ca bundle
// matches the provided value before the polling timeout.
func pollForAPIService(t *testing.T, client apiserviceclientv1.APIServiceInterface, name string, expectedCABundle []byte) (*apiregv1.APIService, error) {
	resourceID := fmt.Sprintf("APIService %q", name)
	obj, err := pollForResource(t, resourceID, pollTimeout, func() (kruntime.Object, error) {
		apiService, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		actualCABundle := apiService.Spec.CABundle
		if len(actualCABundle) == 0 {
			return nil, fmt.Errorf("ca bundle not injected")
		}
		if !bytes.Equal(actualCABundle, expectedCABundle) {
			return nil, fmt.Errorf("ca bundle does not match the expected value")
		}
		return apiService, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*apiregv1.APIService), nil
}

// pollForCRD returns the specified CustomResourceDefinition if the ca
// bundle for its conversion webhook config matches the provided value
// before the polling timeout.
func pollForCRD(t *testing.T, client apiextclient.CustomResourceDefinitionInterface, name string, expectedCABundle []byte) (*apiext.CustomResourceDefinition, error) {
	resourceID := fmt.Sprintf("CustomResourceDefinition %q", name)
	obj, err := pollForResource(t, resourceID, pollTimeout, func() (kruntime.Object, error) {
		crd, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if crd.Spec.Conversion == nil || crd.Spec.Conversion.Webhook == nil || crd.Spec.Conversion.Webhook.ClientConfig == nil {
			return nil, fmt.Errorf("spec.conversion.webhook.webhook.clientConfig not set")
		}
		actualCABundle := crd.Spec.Conversion.Webhook.ClientConfig.CABundle
		if len(actualCABundle) == 0 {
			return nil, fmt.Errorf("ca bundle not injected")
		}
		if !bytes.Equal(actualCABundle, expectedCABundle) {
			return nil, fmt.Errorf("ca bundle does not match the expected value")
		}
		return crd, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*apiext.CustomResourceDefinition), nil
}

// pollForMutatingWebhookConfiguration returns the specified
// MutatingWebhookConfiguration if the ca bundle for all its webhooks match the
// provided value before the polling timeout.
func pollForMutatingWebhookConfiguration(t *testing.T, client admissionregclient.MutatingWebhookConfigurationInterface, name string, expectedCABundle []byte) (*admissionreg.MutatingWebhookConfiguration, error) {
	resourceID := fmt.Sprintf("MutatingWebhookConfiguration %q", name)
	obj, err := pollForResource(t, resourceID, pollTimeout, func() (kruntime.Object, error) {
		webhookConfig, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		for _, webhook := range webhookConfig.Webhooks {
			err := checkWebhookCABundle(webhook.Name, expectedCABundle, webhook.ClientConfig.CABundle)
			if err != nil {
				return nil, err
			}
		}
		return webhookConfig, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*admissionreg.MutatingWebhookConfiguration), nil
}

// pollForValidatingWebhookConfiguration returns the specified
// ValidatingWebhookConfiguration if the ca bundle for all its webhooks match the
// provided value before the polling timeout.
func pollForValidatingWebhookConfiguration(t *testing.T, client admissionregclient.ValidatingWebhookConfigurationInterface, name string, expectedCABundle []byte) (*admissionreg.ValidatingWebhookConfiguration, error) {
	resourceID := fmt.Sprintf("ValidatingWebhookConfiguration %q", name)
	obj, err := pollForResource(t, resourceID, pollTimeout, func() (kruntime.Object, error) {
		webhookConfig, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		for _, webhook := range webhookConfig.Webhooks {
			err := checkWebhookCABundle(webhook.Name, expectedCABundle, webhook.ClientConfig.CABundle)
			if err != nil {
				return nil, err
			}
		}
		return webhookConfig, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*admissionreg.ValidatingWebhookConfiguration), nil
}

// checkWebhookCABundle checks that the ca bundle for the named webhook matches
// the expected value.
func checkWebhookCABundle(webhookName string, expectedCABundle, actualCABundle []byte) error {
	if len(actualCABundle) == 0 {
		return fmt.Errorf("ca bundle not injected for webhook %q", webhookName)
	}
	if !bytes.Equal(actualCABundle, expectedCABundle) {
		return fmt.Errorf("ca bundle does not match the expected value for webhook %q", webhookName)
	}
	return nil
}

// setInjectionAnnotation sets the annotation that will trigger the
// injection of a ca bundle.
// pollForResource returns a kruntime.Object if the accessor returns without error before the timeout.
func pollForResource(t *testing.T, resourceID string, timeout time.Duration, accessor func() (kruntime.Object, error)) (kruntime.Object, error) {
	var obj kruntime.Object
	err := wait.PollImmediate(pollInterval, timeout, func() (bool, error) {
		o, err := accessor()
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			tlogf(t, "an error occurred while polling for %s: %v", resourceID, err)
			return false, nil
		}
		obj = o
		return true, nil
	})
	return obj, err
}

func tlogf(t *testing.T, fmt string, args ...interface{}) {
	argsWithTimestamp := []interface{}{time.Now().Format(time.RFC1123Z)}
	argsWithTimestamp = append(argsWithTimestamp, args...)
	t.Logf("%s: "+fmt, argsWithTimestamp...)
}

func waitForPodPhase(t *testing.T, client *kubernetes.Clientset, name, namespace string, phase v1.PodPhase) error {
	return wait.PollImmediate(5*time.Second, 5*time.Minute, func() (bool, error) {
		pod, err := client.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			tlogf(t, "fetching test pod from apiserver failed: %v", err)
			return false, nil
		}
		if pod.Status.Phase == v1.PodFailed {
			return false, fmt.Errorf("pod %s/%s failed", namespace, name)
		}
		return pod.Status.Phase == phase, nil
	})
}

func getPodLogs(t *testing.T, client *kubernetes.Clientset, name, namespace string) (string, error) {
	rc, err := client.CoreV1().Pods(namespace).GetLogs(name, &v1.PodLogOptions{}).Stream(context.TODO())
	if err != nil {
		return "", err
	}
	defer rc.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(rc)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func deletePod(t *testing.T, client *kubernetes.Clientset, name, namespace string) {
	err := client.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if errors.IsNotFound(err) {
		return
	}
	if err != nil {
		t.Errorf("failed to delete pod: %v", err)
	}
}

func TestE2E(t *testing.T) {
	// use /tmp/admin.conf (placed by ci-operator) or KUBECONFIG env
	confPath := "/tmp/admin.conf"
	if conf := os.Getenv("KUBECONFIG"); conf != "" {
		confPath = conf
	}

	// load client
	client, err := clientcmd.LoadFromFile(confPath)
	if err != nil {
		t.Fatalf("error loading config: %v", err)
	}
	adminConfig, err := clientcmd.NewDefaultClientConfig(*client, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("error loading admin config: %v", err)
	}
	adminClient, err := kubernetes.NewForConfig(adminConfig)
	if err != nil {
		t.Fatalf("error getting admin client: %v", err)
	}

	// the service-serving-cert-operator and controllers should be running as a stock OpenShift component. our first test is to
	// verify that all of the components are running.
	checkComponents(t, adminClient)

	// test the main feature. annotate service -> created secret
	// NOTE: This test is also available in the OTE framework (test/e2e/e2e.go).
	// This duplication is temporary until we fully migrate to OTE and validate the new e2e jobs.
	// Eventually, all tests will run only through the OTE framework.
	t.Run("serving-cert-annotation", func(t *testing.T) {
		for _, headless := range []bool{false, true} {
			t.Run(fmt.Sprintf("headless=%v", headless), func(t *testing.T) {
				testServingCertAnnotation(t, headless)
			})
		}
	})

	// test modified data in serving-cert-secret will regenerated
	// NOTE: This test is also available in the OTE framework (test/e2e/e2e.go).
	// This duplication is temporary until we fully migrate to OTE and validate the new e2e jobs.
	// Eventually, all tests will run only through the OTE framework.
	t.Run("serving-cert-secret-modify-bad-tlsCert", func(t *testing.T) {
		for _, headless := range []bool{false, true} {
			t.Run(fmt.Sprintf("headless=%v", headless), func(t *testing.T) {
				testServingCertSecretModifyBadTLSCert(t, headless)
			})
		}
	})

	// test extra data in serving-cert-secret will be removed
	// NOTE: This test is also available in the OTE framework (test/e2e/e2e.go).
	// This duplication is temporary until we fully migrate to OTE and validate the new e2e jobs.
	// Eventually, all tests will run only through the OTE framework.
	t.Run("serving-cert-secret-add-data", func(t *testing.T) {
		for _, headless := range []bool{false, true} {
			t.Run(fmt.Sprintf("headless=%v", headless), func(t *testing.T) {
				testServingCertSecretAddData(t, headless)
			})
		}
	})

	// make sure that deleting service-cert-secret regenerates a secret again,
	// and that the secret allows successful connections in practice.
	// NOTE: This test is also available in the OTE framework (test/e2e/e2e.go).
	// This duplication is temporary until we fully migrate to OTE and validate the new e2e jobs.
	// Eventually, all tests will run only through the OTE framework.
	t.Run("serving-cert-secret-delete-data", func(t *testing.T) {
		testServingCertSecretDeleteData(t)
	})

	// make sure that deleting aservice-cert-secret regenerates a secret again,
	// and that the secret allows successful connections in practice.
	// NOTE: This test is also available in the OTE framework (test/e2e/e2e.go).
	// This duplication is temporary until we fully migrate to OTE and validate the new e2e jobs.
	// Eventually, all tests will run only through the OTE framework.
	t.Run("headless-stateful-serving-cert-secret-delete-data", func(t *testing.T) {
		testHeadlessStatefulServingCertSecretDeleteData(t)
	})

	// test ca bundle injection configmap
	// NOTE: This test is also available in the OTE framework (test/e2e/e2e.go).
	// This duplication is temporary until we fully migrate to OTE and validate the new e2e jobs.
	// Eventually, all tests will run only through the OTE framework.
	t.Run("ca-bundle-injection-configmap", func(t *testing.T) {
		testCABundleInjectionConfigMap(t)
	})

	// test updated data in ca bundle injection configmap will be stomped on
	t.Run("ca-bundle-injection-configmap-update", func(t *testing.T) {
		testCABundleInjectionConfigMapUpdate(t)
	})

	// test vulnerable-legacy ca bundle injection configmap
	// NOTE: This test is also available in the OTE framework (test/e2e/e2e.go).
	// This duplication is temporary until we fully migrate to OTE and validate the new e2e jobs.
	// Eventually, all tests will run only through the OTE framework.
	t.Run("vulnerable-legacy-ca-bundle-injection-configmap", func(t *testing.T) {
		testVulnerableLegacyCABundleInjectionConfigMap(t)
	})

	// test metrics collection and service CA metrics
	// NOTE: This test is also available in the OTE framework (test/e2e/e2e.go).
	// This duplication is temporary until we fully migrate to OTE and validate the new e2e jobs.
	// Eventually, all tests will run only through the OTE framework.
	t.Run("metrics", func(t *testing.T) {
		t.Run("collection", func(t *testing.T) {
			testMetricsCollection(t)
		})

		t.Run("service-ca-metrics", func(t *testing.T) {
			testServiceCAMetrics(t)
		})
	})

	t.Run("refresh-CA", func(t *testing.T) {
		ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		defer cleanup()

		// create secrets
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		testHeadlessServiceName := "test-headless-service-" + randSeq(5)
		testHeadlessSecretName := "test-headless-secret-" + randSeq(5)

		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name, false)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}
		if err = createServingCertAnnotatedService(adminClient, testHeadlessSecretName, testHeadlessServiceName, ns.Name, true); err != nil {
			t.Fatalf("error creating annotated headless service: %v", err)
		}

		secret, err := pollForServiceServingSecretWithReturn(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}
		secretCopy := secret.DeepCopy()
		headlessSecret, err := pollForServiceServingSecretWithReturn(adminClient, testHeadlessSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}
		headlessSecretCopy := headlessSecret.DeepCopy()

		// create configmap
		testConfigMapName := "test-configmap-" + randSeq(5)

		err = createAnnotatedCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated configmap: %v", err)
		}

		configmap, err := pollForCABundleInjectionConfigMapWithReturn(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching ca bundle injection configmap: %v", err)
		}
		configmapCopy := configmap.DeepCopy()
		err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking ca bundle injection configmap: %v", err)
		}

		// delete ca secret
		err = adminClient.CoreV1().Secrets(serviceCAControllerNamespace).Delete(context.TODO(), signingKeySecretName, metav1.DeleteOptions{})
		if err != nil {
			t.Fatalf("error deleting signing key: %v", err)
		}

		// make sure it's recreated
		err = pollForCARecreation(adminClient)
		if err != nil {
			t.Fatalf("signing key was not recreated: %v", err)
		}

		err = pollForConfigMapChange(t, adminClient, configmapCopy, api.InjectionDataKey)
		if err != nil {
			t.Fatalf("configmap bundle did not change: %v", err)
		}

		err = pollForSecretChange(t, adminClient, secretCopy, v1.TLSCertKey, v1.TLSPrivateKeyKey)
		if err != nil {
			t.Fatalf("secret cert did not change: %v", err)
		}
		if err := pollForSecretChange(t, adminClient, headlessSecretCopy); err != nil {
			t.Fatalf("headless secret cert did not change: %v", err)
		}
	})

	// This test triggers rotation by updating the CA to have an
	// expiry that is less than the minimum required duration and then
	// validates that both refreshed and unrefreshed clients and
	// servers can continue to communicate in a trusted fashion.
	t.Run("time-based-ca-rotation", func(t *testing.T) {
		checkCARotation(t, adminClient, adminConfig, triggerTimeBasedRotation)
	})

	// This test triggers rotation by updating the operator
	// configuration to force rotation and then validates that both
	// refreshed and unrefreshed clients and servers can continue to
	// communicate in a trusted fashion.
	t.Run("forced-ca-rotation", func(t *testing.T) {
		checkCARotation(t, adminClient, adminConfig, triggerForcedRotation)
	})

	t.Run("apiservice-ca-bundle-injection", func(t *testing.T) {
		client := apiserviceclient.NewForConfigOrDie(adminConfig).ApiregistrationV1().APIServices()

		// Create an api service with the injection annotation
		randomGroup := fmt.Sprintf("e2e-%s", randSeq(10))
		version := "v1alpha1"
		obj := &apiregv1.APIService{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("%s.%s", version, randomGroup),
			},
			Spec: apiregv1.APIServiceSpec{
				Group:                randomGroup,
				Version:              version,
				GroupPriorityMinimum: 1,
				VersionPriority:      1,
				// A service must be specified for validation to
				// accept a cabundle.
				Service: &apiregv1.ServiceReference{
					Namespace: "foo",
					Name:      "foo",
				},
			},
		}
		setInjectionAnnotation(&obj.ObjectMeta)
		createdObj, err := client.Create(context.TODO(), obj, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("error creating api service: %v", err)
		}
		defer func() {
			err := client.Delete(context.TODO(), obj.Name, metav1.DeleteOptions{})
			if err != nil {
				t.Errorf("Failed to cleanup api service: %v", err)
			}
		}()

		// Retrieve the expected CA bundle
		expectedCABundle, err := pollForSigningCABundle(t, adminClient)
		if err != nil {
			t.Fatalf("error retrieving the signing ca bundle: %v", err)
		}

		// Wait for the expected bundle to be injected
		injectedObj, err := pollForAPIService(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be injected: %v", err)
		}

		// Set an invalid ca bundle
		injectedObj.Spec.CABundle = append(injectedObj.Spec.CABundle, []byte("garbage")...)
		_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("error updated api service: %v", err)
		}

		// Check that the expected ca bundle is restored
		_, err = pollForAPIService(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
		}
	})

	t.Run("crd-ca-bundle-injection", func(t *testing.T) {
		client := apiextclient.NewForConfigOrDie(adminConfig).CustomResourceDefinitions()

		// Create a crd with the injection annotation
		randomGroup := fmt.Sprintf("e2e-%s.example.com", randSeq(10))
		pluralName := "cabundleinjectiontargets"
		version := "v1beta1"
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
					// CA bundle will only be injected for a webhook converter
					Strategy: apiext.WebhookConverter,
					Webhook: &apiext.WebhookConversion{
						// CA bundle will be set on the following struct
						ClientConfig: &apiext.WebhookClientConfig{
							Service: &apiext.ServiceReference{
								Namespace: "foo",
								Name:      "foo",
							},
						},
						ConversionReviewVersions: []string{
							version,
						},
					},
				},
				// At least one version must be defined for a v1 crd to be valid
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
		setInjectionAnnotation(&obj.ObjectMeta)
		createdObj, err := client.Create(context.TODO(), obj, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("error creating crd: %v", err)
		}
		defer func() {
			err := client.Delete(context.TODO(), obj.Name, metav1.DeleteOptions{})
			if err != nil {
				t.Errorf("Failed to cleanup crd: %v", err)
			}
		}()

		// Retrieve the expected CA bundle
		expectedCABundle, err := pollForSigningCABundle(t, adminClient)
		if err != nil {
			t.Fatalf("error retrieving the signing ca bundle: %v", err)
		}

		// Wait for the expected bundle to be injected
		injectedObj, err := pollForCRD(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be injected: %v", err)
		}

		// Set an invalid ca bundle
		whClientConfig := injectedObj.Spec.Conversion.Webhook.ClientConfig
		whClientConfig.CABundle = append(whClientConfig.CABundle, []byte("garbage")...)
		_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("error updated crd: %v", err)
		}

		// Check that the expected ca bundle is restored
		_, err = pollForCRD(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
		}
	})

	// Common webhook config
	webhookClientConfig := admissionreg.WebhookClientConfig{
		// A service must be specified for validation to
		// accept a cabundle.
		Service: &admissionreg.ServiceReference{
			Namespace: "foo",
			Name:      "foo",
		},
	}
	sideEffectNone := admissionreg.SideEffectClassNone

	t.Run("mutatingwebhook-ca-bundle-injection", func(t *testing.T) {
		client := adminClient.AdmissionregistrationV1().MutatingWebhookConfigurations()
		obj := &admissionreg.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "e2e-",
			},
			Webhooks: []admissionreg.MutatingWebhook{
				// Specify 2 webhooks to ensure more than 1 webhook will be updated
				{
					Name:                    "e2e-1.example.com",
					ClientConfig:            webhookClientConfig,
					SideEffects:             &sideEffectNone,
					AdmissionReviewVersions: []string{"v1beta1"},
				},
				{
					Name:                    "e2e-2.example.com",
					ClientConfig:            webhookClientConfig,
					SideEffects:             &sideEffectNone,
					AdmissionReviewVersions: []string{"v1beta1"},
				},
			},
		}
		// webhooks to add after initial creation to ensure
		// updates can be made for more than the original number of webhooks.
		webhooksToAdd := []admissionreg.MutatingWebhook{
			{
				Name:                    "e2e-3.example.com",
				ClientConfig:            webhookClientConfig,
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1"},
			},
		}
		setInjectionAnnotation(&obj.ObjectMeta)
		createdObj, err := client.Create(context.TODO(), obj, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("error creating mutating webhook configuration: %v", err)
		}
		defer func() {
			err := client.Delete(context.TODO(), createdObj.Name, metav1.DeleteOptions{})
			if err != nil {
				t.Errorf("Failed to cleanup mutating webhook configuration: %v", err)
			}
		}()

		// Retrieve the expected CA bundle
		expectedCABundle, err := pollForSigningCABundle(t, adminClient)
		if err != nil {
			t.Fatalf("error retrieving the expected ca bundle: %v", err)
		}

		// Poll for the updated webhook configuration
		injectedObj, err := pollForMutatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be injected: %v", err)
		}

		// Set an invalid ca bundle
		clientConfig := injectedObj.Webhooks[0].ClientConfig
		clientConfig.CABundle = append(clientConfig.CABundle, []byte("garbage")...)
		_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("error updated mutating webhook configuration: %v", err)
		}

		// Check that the ca bundle is restored
		injectedObj, err = pollForMutatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
		}

		// Add an additional webhook and make sure CA bundle exists for all
		injectedObj.Webhooks = append(injectedObj.Webhooks, webhooksToAdd...)
		_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("error updating mutating webhook configuration: %v", err)
		}

		// Check that the ca bundle for all webhooks (old and new)
		_, err = pollForMutatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
		}
	})

	t.Run("validatingwebhook-ca-bundle-injection", func(t *testing.T) {
		client := adminClient.AdmissionregistrationV1().ValidatingWebhookConfigurations()
		obj := &admissionreg.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "e2e-",
			},
			Webhooks: []admissionreg.ValidatingWebhook{
				// Specify 2 webhooks to ensure more than 1 webhook will be updated
				{
					Name:                    "e2e-1.example.com",
					ClientConfig:            webhookClientConfig,
					SideEffects:             &sideEffectNone,
					AdmissionReviewVersions: []string{"v1beta1"},
				},
				{
					Name:                    "e2e-2.example.com",
					ClientConfig:            webhookClientConfig,
					SideEffects:             &sideEffectNone,
					AdmissionReviewVersions: []string{"v1beta1"},
				},
			},
		}
		// webhooks to add after initial creation to ensure
		// updates can be made for more than the original number of webhooks.
		webhooksToAdd := []admissionreg.ValidatingWebhook{
			{
				Name:                    "e2e-3.example.com",
				ClientConfig:            webhookClientConfig,
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1"},
			},
		}
		setInjectionAnnotation(&obj.ObjectMeta)
		createdObj, err := client.Create(context.TODO(), obj, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("error creating validating webhook configuration: %v", err)
		}
		defer func() {
			err := client.Delete(context.TODO(), createdObj.Name, metav1.DeleteOptions{})
			if err != nil {
				t.Errorf("Failed to cleanup validating webhook configuration: %v", err)
			}
		}()

		// Retrieve the expected CA bundle
		expectedCABundle, err := pollForSigningCABundle(t, adminClient)
		if err != nil {
			t.Fatalf("error retrieving the expected ca bundle: %v", err)
		}

		// Poll for the updated webhook configuration
		injectedObj, err := pollForValidatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be injected: %v", err)
		}

		// Set an invalid ca bundle
		clientConfig := injectedObj.Webhooks[0].ClientConfig
		clientConfig.CABundle = append(clientConfig.CABundle, []byte("garbage")...)
		_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("error updated validating webhook configuration: %v", err)
		}

		// Check that the ca bundle is restored
		injectedObj, err = pollForValidatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
		}

		// Add an additional webhook and make sure CA bundle exists for all
		injectedObj.Webhooks = append(injectedObj.Webhooks, webhooksToAdd...)
		_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("error updating validating webhook configuration: %v", err)
		}

		// Check that the ca bundle for all webhooks (old and new)
		_, err = pollForValidatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
		}
	})
}
