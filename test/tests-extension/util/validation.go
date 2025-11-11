package util

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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

// CheckClusterOperatorsHealthy verifies cluster operators are available and not degraded
// This is a lightweight check that verifies kube-apiserver is responsive
func CheckClusterOperatorsHealthy(client kubernetes.Interface) error {
	// Verify kube-apiserver is responsive
	_, err := client.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("kube-apiserver not responsive: %v", err)
	}

	// Check that we can list nodes (indicates cluster is functional)
	_, err = client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{Limit: 1})
	if err != nil {
		return fmt.Errorf("cannot list nodes, cluster may be unhealthy: %v", err)
	}

	return nil
}

// CheckClusterOperatorStatus checks specific OpenShift cluster operator status
func CheckClusterOperatorStatus(config *rest.Config, operatorNames ...string) error {
	configClient, err := configclient.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create config client: %v", err)
	}

	for _, name := range operatorNames {
		co, err := configClient.ConfigV1().ClusterOperators().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get cluster operator %s: %v", name, err)
		}

		// Check conditions
		available := false
		degraded := true
		progressing := true

		for _, condition := range co.Status.Conditions {
			switch condition.Type {
			case configv1.OperatorAvailable:
				if condition.Status == configv1.ConditionTrue {
					available = true
				}
			case configv1.OperatorDegraded:
				if condition.Status == configv1.ConditionFalse {
					degraded = false
				}
			case configv1.OperatorProgressing:
				if condition.Status == configv1.ConditionFalse {
					progressing = false
				}
			}
		}

		if !available {
			return fmt.Errorf("cluster operator %s is not available", name)
		}
		if degraded {
			return fmt.Errorf("cluster operator %s is degraded", name)
		}
		if progressing {
			return fmt.Errorf("cluster operator %s is progressing", name)
		}
	}

	return nil
}

// WaitForClusterOperatorHealthy waits for cluster operators to become healthy
// This is useful after resource-intensive operations that may stress the kube-apiserver
func WaitForClusterOperatorHealthy(config *rest.Config, timeoutMinutes int, operatorNames ...string) error {
	configClient, err := configclient.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create config client: %v", err)
	}

	pollInterval := 10 * time.Second
	timeout := time.Duration(timeoutMinutes) * time.Minute
	startTime := time.Now()

	for {
		allHealthy := true
		var unhealthyReasons []string

		for _, name := range operatorNames {
			co, err := configClient.ConfigV1().ClusterOperators().Get(context.TODO(), name, metav1.GetOptions{})
			if err != nil {
				unhealthyReasons = append(unhealthyReasons, fmt.Sprintf("%s: failed to get operator: %v", name, err))
				allHealthy = false
				continue
			}

			// Check conditions
			available := false
			degraded := true
			progressing := true

			for _, condition := range co.Status.Conditions {
				switch condition.Type {
				case configv1.OperatorAvailable:
					if condition.Status == configv1.ConditionTrue {
						available = true
					}
				case configv1.OperatorDegraded:
					if condition.Status == configv1.ConditionFalse {
						degraded = false
					}
				case configv1.OperatorProgressing:
					if condition.Status == configv1.ConditionFalse {
						progressing = false
					}
				}
			}

			if !available {
				unhealthyReasons = append(unhealthyReasons, fmt.Sprintf("%s: not available", name))
				allHealthy = false
			}
			if degraded {
				unhealthyReasons = append(unhealthyReasons, fmt.Sprintf("%s: degraded", name))
				allHealthy = false
			}
			if progressing {
				unhealthyReasons = append(unhealthyReasons, fmt.Sprintf("%s: progressing", name))
				allHealthy = false
			}
		}

		if allHealthy {
			return nil
		}

		// Check timeout
		if time.Since(startTime) >= timeout {
			return fmt.Errorf("timed out waiting for cluster operators to become healthy after %d minutes: %s",
				timeoutMinutes, strings.Join(unhealthyReasons, "; "))
		}

		// Wait before next poll
		time.Sleep(pollInterval)
	}
}
