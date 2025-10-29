package util

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CheckServiceServingCertSecretData checks the service serving cert secret data
func CheckServiceServingCertSecretData(client kubernetes.Interface, secretName, namespace string) ([]byte, bool, error) {
	secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, false, err
	}
	certBytes, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, false, fmt.Errorf("serving cert secret %s/%s is missing %s", namespace, secretName, corev1.TLSCertKey)
	}
	keyBytes, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, false, fmt.Errorf("serving cert secret %s/%s is missing %s", namespace, secretName, corev1.TLSPrivateKeyKey)
	}
	if len(certBytes) == 0 {
		return nil, false, fmt.Errorf("serving cert secret %s/%s has an empty %s", namespace, secretName, corev1.TLSCertKey)
	}
	if len(keyBytes) == 0 {
		return nil, false, fmt.Errorf("serving cert secret %s/%s has an empty %s", namespace, secretName, corev1.TLSPrivateKeyKey)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, false, fmt.Errorf("failed to decode pem block")
	}
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse certificate: %v", err)
	}
	return certBytes, true, nil
}

// CheckConfigMapCABundleInjectionData checks the CA bundle injection configmap data
func CheckConfigMapCABundleInjectionData(client kubernetes.Interface, configMapName, namespace string) error {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	injectedData, ok := cm.Data["service-ca.crt"]
	if !ok {
		return fmt.Errorf("ca bundle injection configmap %s/%s is missing %s", namespace, configMapName, "service-ca.crt")
	}
	if len(injectedData) == 0 {
		return fmt.Errorf("ca bundle injection configmap %s/%s has an empty %s", namespace, configMapName, "service-ca.crt")
	}
	return nil
}

// CheckComponents verifies that the components of the operator are running.
func CheckComponents(client kubernetes.Interface) error {
	componentConfigs := []struct {
		namespace string
		podPrefix string
	}{
		{"openshift-service-ca-operator", "service-ca-operator"},
		{"openshift-service-ca", "service-ca"},
	}
	for _, cfg := range componentConfigs {
		pods, err := client.CoreV1().Pods(cfg.namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list pods in namespace %q: %v", cfg.namespace, err)
		}
		podFound := false
		for _, pod := range pods.Items {
			if strings.HasPrefix(pod.GetName(), cfg.podPrefix) {
				podFound = true
				break
			}
		}
		if !podFound {
			return fmt.Errorf("no pods with prefix %q found running in namespace %q", cfg.podPrefix, cfg.namespace)
		}
	}
	return nil
}
