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
	if len(secret.Data) != 2 {
		return nil, false, fmt.Errorf("unexpected serving cert secret data map length: %v", len(secret.Data))
	}
	certBytes, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, false, fmt.Errorf("unexpected serving cert secret data: %v", secret.Data)
	}
	keyBytes, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, false, fmt.Errorf("unexpected serving cert secret data: %v", secret.Data)
	}
	if len(certBytes) == 0 || len(keyBytes) == 0 {
		return nil, false, fmt.Errorf("unexpected serving cert secret data: %v", secret.Data)
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
	if len(cm.Data) != 1 {
		return fmt.Errorf("unexpected ca bundle injection configmap data map length: %v", len(cm.Data))
	}
	ok := true
	_, ok = cm.Data[InjectionDataKey]
	if !ok {
		return fmt.Errorf("unexpected ca bundle injection configmap data: %v", cm.Data)
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
