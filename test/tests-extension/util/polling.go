package util

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

const (
	pollInterval = 5 * time.Second
	pollTimeout  = 60 * time.Second
)

// PollForServiceServingSecret polls for a service serving secret to be created
func PollForServiceServingSecret(client kubernetes.Interface, secretName, namespace string) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		_, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

// PollForCABundleInjectionConfigMap polls for a CA bundle injection configmap to be created
func PollForCABundleInjectionConfigMap(client kubernetes.Interface, configMapName, namespace string) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		_, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

// PollForServiceServingSecretWithReturn polls for service serving secret and returns it
func PollForServiceServingSecretWithReturn(client kubernetes.Interface, secretName, namespace string) (*corev1.Secret, error) {
	var secret *corev1.Secret
	err := wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		s, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		secret = s
		return true, nil
	})
	return secret, err
}

// PollForCABundleInjectionConfigMapWithReturn polls for CA bundle injection configmap and returns it
func PollForCABundleInjectionConfigMapWithReturn(client kubernetes.Interface, configMapName, namespace string) (*corev1.ConfigMap, error) {
	var configmap *corev1.ConfigMap
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

// PollForConfigMapCAInjection polls for configmap CA injection
func PollForConfigMapCAInjection(client kubernetes.Interface, configMapName, namespace string) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}

		if len(cm.Data) != 1 {
			return false, nil
		}
		_, ok := cm.Data[InjectionDataKey]
		if !ok {
			return false, nil
		}
		return true, nil
	})
}

// PollForResource returns a kruntime.Object if the accessor returns without error before the timeout.
func PollForResource(resourceID string, timeout time.Duration, accessor func() (kruntime.Object, error)) (kruntime.Object, error) {
	var obj kruntime.Object
	err := wait.PollImmediate(pollInterval, timeout, func() (bool, error) {
		o, err := accessor()
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			fmt.Printf("an error occurred while polling for %s: %v\n", resourceID, err)
			return false, nil
		}
		obj = o
		return true, nil
	})
	return obj, err
}
