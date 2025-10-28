package util

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

const (
	serviceCAControllerNamespace = "openshift-service-ca"
	signingKeySecretName         = "signing-key"
	rotationTimeout              = 5 * time.Minute
	rotationPollTimeout          = 4 * time.Minute
)

// PollForCARecreation polls for the signing secret to be re-created
func PollForCARecreation(client kubernetes.Interface) error {
	return wait.PollImmediate(time.Second, rotationPollTimeout, func() (bool, error) {
		_, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
		if err != nil {
			return false, nil
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
		err = CheckData(oldData, s.Data)
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
	return PollForUpdatedConfigMap(client, namespace, name, api.InjectionDataKey, timeout, oldValue)
}

// PollForSigningCABundle returns the bytes for the bundle key of the signing ca bundle configmap
func PollForSigningCABundle(client kubernetes.Interface) ([]byte, error) {
	return PollForUpdatedConfigMap(client, serviceCAControllerNamespace, api.SigningCABundleConfigMapName, api.BundleDataKey, 60*time.Second, nil)
}

// PollForUpdatedConfigMap returns the given configmap if its data changes
func PollForUpdatedConfigMap(client kubernetes.Interface, namespace, name, key string, timeout time.Duration, oldValue []byte) ([]byte, error) {
	var configMap *corev1.ConfigMap
	err := wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if len(cm.Data) == 0 {
			return false, fmt.Errorf("configmap has no data")
		}
		value, ok := cm.Data[key]
		if !ok {
			return false, fmt.Errorf("key %q is missing", key)
		}
		if oldValue != nil && value == string(oldValue) {
			return false, fmt.Errorf("value for key %q has not changed", key)
		}
		configMap = cm
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return []byte(configMap.Data[key]), nil
}

// CheckCARotation is a placeholder for CA rotation testing
func CheckCARotation(client kubernetes.Interface, config *rest.Config, triggerRotation func(kubernetes.Interface, *rest.Config) error) error {
	// This is a simplified version - in a real implementation, this would:
	// 1. Create test resources (services, configmaps)
	// 2. Trigger rotation
	// 3. Verify that all resources are updated with new CA
	return triggerRotation(client, config)
}

// TriggerTimeBasedRotation is a placeholder for time-based rotation
func TriggerTimeBasedRotation(client kubernetes.Interface, config *rest.Config) error {
	// In a real implementation, this would:
	// 1. Get current CA
	// 2. Create a new CA with short expiry
	// 3. Update the secret
	return nil
}

// TriggerForcedRotation is a placeholder for forced rotation
func TriggerForcedRotation(client kubernetes.Interface, config *rest.Config) error {
	// In a real implementation, this would:
	// 1. Update operator config to force rotation
	// 2. Wait for rotation to complete
	return nil
}
