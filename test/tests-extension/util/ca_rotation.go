package util

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/operator"
	testutil "github.com/openshift/service-ca-operator/test/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/cert"
	"k8s.io/utils/clock"
)

const (
	serviceCAControllerNamespace = "openshift-service-ca"
	signingKeySecretName         = "signing-key"
	rotationTimeout              = 5 * time.Minute
	rotationPollTimeout          = 4 * time.Minute
	signingCertificateLifetime   = 790 * 24 * time.Hour
)

// PollForCARecreation polls for the signing secret to be re-created
func PollForCARecreation(client kubernetes.Interface) error {
	return wait.PollImmediate(time.Second, rotationPollTimeout, func() (bool, error) {
		_, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})
}

// PollForUpdatedServingCert returns the cert and key PEM if it changes
func PollForUpdatedServingCert(client kubernetes.Interface, namespace, name string, timeout time.Duration, oldCertValue, oldKeyValue []byte) ([]byte, []byte, error) {
	secret, err := PollForUpdatedSecret(client, namespace, name, timeout, map[string][]byte{
		corev1.TLSCertKey:       oldCertValue,
		corev1.TLSPrivateKeyKey: oldKeyValue,
	})
	if err != nil {
		return nil, nil, err
	}
	return secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey], nil
}

// PollForUpdatedSecret returns the given secret if its data changes
func PollForUpdatedSecret(client kubernetes.Interface, namespace, name string, timeout time.Duration, oldData map[string][]byte) (*corev1.Secret, error) {
	var secret *corev1.Secret
	err := wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		s, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		err = testutil.CheckData(oldData, s.Data)
		if err != nil {
			return false, nil
		}
		secret = s
		return true, nil
	})
	return secret, err
}

// PollForInjectedCABundle returns the bytes for the injection key in the targeted configmap
func PollForInjectedCABundle(client kubernetes.Interface, namespace, name string, timeout time.Duration, oldValue []byte) ([]byte, error) {
	return PollForUpdatedConfigMap(client, namespace, name, InjectionDataKey, timeout, oldValue)
}

// PollForSigningCABundle returns the bytes for the bundle key of the signing ca bundle configmap
func PollForSigningCABundle(client kubernetes.Interface) ([]byte, error) {
	return PollForUpdatedConfigMap(client, serviceCAControllerNamespace, SigningCABundleConfigMapName, BundleDataKey, 60*time.Second, nil)
}

// PollForUpdatedConfigMap returns the given configmap if its data changes
// PollForUpdatedConfigMap polls for a ConfigMap with the specified namespace and name until either:
// - The ConfigMap's specified key value changes from oldValue (if oldValue is not nil)
// - The ConfigMap contains data and the specified key exists (if oldValue is nil)
// - The timeout duration is reached
// Returns the updated ConfigMap's key value if successful, or an error if the timeout is reached or other error occurs
func PollForUpdatedConfigMap(client kubernetes.Interface, namespace, name, key string, timeout time.Duration, oldValue []byte) ([]byte, error) {
	var configMap *corev1.ConfigMap
	err := wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if len(cm.Data) == 0 {
			return false, nil // Keep polling if no data yet
		}
		value, ok := cm.Data[key]
		if !ok {
			return false, nil // Keep polling if key missing
		}
		if oldValue != nil && value == string(oldValue) {
			return false, nil // Keep polling if value hasn't changed
		}
		configMap = cm
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if configMap == nil {
		return nil, fmt.Errorf("timeout waiting for configmap %s/%s key %q to change", namespace, name, key)
	}
	return []byte(configMap.Data[key]), nil
}

// CheckCARotation validates CA rotation by creating test resources, triggering rotation,
// and verifying that certs and bundles are updated correctly
func CheckCARotation(client kubernetes.Interface, config *rest.Config, triggerRotation func(kubernetes.Interface, *rest.Config) error) error {
	// Get pre-rotation CA bundle to validate rotation occurred
	oldBundlePEM, err := PollForSigningCABundle(client)
	if err != nil {
		return fmt.Errorf("error retrieving pre-rotation ca bundle: %v", err)
	}

	// Trigger CA rotation
	if err := triggerRotation(client, config); err != nil {
		return fmt.Errorf("error triggering rotation: %v", err)
	}

	// Verify the CA bundle was updated (rotation completed)
	newBundlePEM, err := PollForUpdatedConfigMap(client, serviceCAControllerNamespace, SigningCABundleConfigMapName, BundleDataKey, rotationTimeout, oldBundlePEM)
	if err != nil {
		return fmt.Errorf("error retrieving post-rotation ca bundle: %v", err)
	}

	// Verify that the bundle actually changed
	if bytes.Equal(oldBundlePEM, newBundlePEM) {
		return fmt.Errorf("CA bundle did not change after rotation")
	}

	return nil
}

// TriggerTimeBasedRotation replaces the current CA cert with one that
// is not valid for the minimum required duration and waits for the CA
// to be rotated.
func TriggerTimeBasedRotation(client kubernetes.Interface, config *rest.Config) error {
	// A rotation-prompting CA cert needs to be a renewed instance
	// (i.e. share the same public and private keys) of the current
	// cert to ensure that trust will be maintained for unrefreshed
	// clients and servers.

	// Retrieve current CA
	secret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error retrieving signing key secret: %v", err)
	}
	// Store the old PEMs for comparison
	oldCACertPEM := secret.Data[corev1.TLSCertKey]
	oldCAKeyPEM := secret.Data[corev1.TLSPrivateKeyKey]

	currentCACerts, err := testutil.PemToCerts(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return fmt.Errorf("error unmarshaling %q: %v", corev1.TLSCertKey, err)
	}
	currentCAKey, err := testutil.PemToKey(secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return fmt.Errorf("error unmarshalling %q: %v", corev1.TLSPrivateKeyKey, err)
	}
	currentCAConfig := &crypto.TLSCertificateConfig{
		Certs: currentCACerts,
		Key:   currentCAKey,
	}

	// Trigger rotation by renewing the current ca with an expiry that
	// is sooner than the minimum required duration.
	renewedCAConfig, err := operator.RenewSelfSignedCertificate(currentCAConfig, 1*time.Hour, true)
	if err != nil {
		return fmt.Errorf("error renewing ca to half-expired form: %v", err)
	}
	renewedCACertPEM, renewedCAKeyPEM, err := renewedCAConfig.GetPEMBytes()
	if err != nil {
		return fmt.Errorf("error encoding renewed ca to pem: %v", err)
	}

	// Write the renewed CA
	secret = &corev1.Secret{
		Type: corev1.SecretTypeTLS,
		ObjectMeta: metav1.ObjectMeta{
			Name:      signingKeySecretName,
			Namespace: serviceCAControllerNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       renewedCACertPEM,
			corev1.TLSPrivateKeyKey: renewedCAKeyPEM,
		},
	}
	_, _, err = resourceapply.ApplySecret(context.Background(), client.CoreV1(), events.NewInMemoryRecorder("test", clock.RealClock{}), secret)
	if err != nil {
		return fmt.Errorf("error updating secret with test CA: %v", err)
	}

	// Wait for CA rotation to complete
	return pollForCARotation(client, oldCACertPEM, oldCAKeyPEM)
}

// TriggerForcedRotation forces the rotation of the current CA via the
// operator config.
func TriggerForcedRotation(client kubernetes.Interface, config *rest.Config) error {
	// Retrieve the cert and key PEM of the current CA to be able to
	// detect when rotation has completed.
	secret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error retrieving signing key secret: %v", err)
	}
	caCertPEM := secret.Data[corev1.TLSCertKey]
	caKeyPEM := secret.Data[corev1.TLSPrivateKeyKey]

	// Set a custom validity duration longer than the default to
	// validate that a custom expiry on rotation is possible.
	defaultDuration := signingCertificateLifetime
	customDuration := defaultDuration + 1*time.Hour

	// Trigger a forced rotation by updating the operator config
	// with a reason.
	if err := forceUnsupportedServiceCAConfigRotation(config, secret, customDuration); err != nil {
		return fmt.Errorf("error forcing rotation: %v", err)
	}

	// Wait for CA rotation to complete
	if err := pollForCARotation(client, caCertPEM, caKeyPEM); err != nil {
		return fmt.Errorf("error waiting for CA rotation: %v", err)
	}

	// Check that the expiry of the new CA is longer than the default
	signingSecret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error retrieving signing key secret after rotation: %v", err)
	}
	rawCert := signingSecret.Data[corev1.TLSCertKey]
	certs, err := cert.ParseCertsPEM(rawCert)
	if err != nil {
		return fmt.Errorf("failed to parse signing secret cert: %v", err)
	}
	if !certs[0].NotAfter.After(time.Now().Add(defaultDuration)) {
		return fmt.Errorf("custom validity duration was not used to generate the new CA")
	}

	return nil
}

// pollForCARotation polls for the signing secret to be changed in
// response to CA rotation.
func pollForCARotation(client kubernetes.Interface, caCertPEM, caKeyPEM []byte) error {
	return wait.PollImmediate(5*time.Second, rotationPollTimeout, func() (bool, error) {
		secret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		// Check if both cert and key are still the same as the old values
		if bytes.Equal(secret.Data[corev1.TLSCertKey], caCertPEM) && bytes.Equal(secret.Data[corev1.TLSPrivateKeyKey], caKeyPEM) {
			return false, nil
		}
		return true, nil
	})
}

// forceUnsupportedServiceCAConfigRotation updates the operator config to force rotation
func forceUnsupportedServiceCAConfigRotation(config *rest.Config, currentSigningKeySecret *corev1.Secret, validityDuration time.Duration) error {
	operatorClient, err := operatorv1client.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("error creating operator client: %v", err)
	}

	var forceRotationReason string
	for i := 0; ; i++ {
		forceRotationReason = fmt.Sprintf("service-ca-test-force-rotation-reason-%d", i)
		if currentSigningKeySecret.Annotations[api.ForcedRotationReasonAnnotationName] != forceRotationReason {
			break
		}
	}

	// Retry update to handle concurrent modifications
	err = wait.PollImmediate(time.Second, 30*time.Second, func() (bool, error) {
		operatorConfig, err := operatorClient.OperatorV1().ServiceCAs().Get(context.TODO(), api.OperatorConfigInstanceName, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error retrieving operator config: %v", err)
		}

		rawUnsupportedServiceCAConfig, err := operator.RawUnsupportedServiceCAConfig(forceRotationReason, validityDuration)
		if err != nil {
			return false, fmt.Errorf("failed to create raw unsupported config overrides: %v", err)
		}
		operatorConfig.Spec.UnsupportedConfigOverrides.Raw = rawUnsupportedServiceCAConfig

		_, err = operatorClient.OperatorV1().ServiceCAs().Update(context.TODO(), operatorConfig, metav1.UpdateOptions{})
		if err != nil {
			// Retry on conflict errors
			if strings.Contains(err.Error(), "the object has been modified") {
				return false, nil
			}
			return false, fmt.Errorf("error updating operator config: %v", err)
		}
		return true, nil
	})

	return err
}
