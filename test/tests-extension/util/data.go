package util

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// RandSeq generates a random sequence of characters
func RandSeq(n int) string {
	// Use nanosecond precision to ensure uniqueness
	now := time.Now()
	rand.Seed(now.UnixNano())
	var letters = []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	// Append nanosecond suffix to ensure uniqueness even with rapid successive calls
	return string(b) + fmt.Sprintf("-%d", now.Nanosecond())
}

// EditServingSecretData edits serving secret data and polls for regeneration
func EditServingSecretData(client kubernetes.Interface, secretName, namespace, keyName string) error {
	secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	// Create a copy and set invalid data (like the original test)
	secretCopy := secret.DeepCopy()
	secretCopy.Data[keyName] = []byte("blah")

	_, err = client.CoreV1().Secrets(namespace).Update(context.TODO(), secretCopy, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	// Poll for secret change (wait for operator to regenerate)
	return PollForSecretChange(client, secretCopy, keyName)
}

// EditConfigMapCABundleInjectionData edits configmap CA bundle injection data and polls for regeneration
func EditConfigMapCABundleInjectionData(client kubernetes.Interface, configMapName, namespace string) error {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	// Create a copy and add extra data (like the original test)
	cmCopy := cm.DeepCopy()
	cmCopy.Data["foo"] = "blah"

	_, err = client.CoreV1().ConfigMaps(namespace).Update(context.TODO(), cmCopy, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	// Poll for configmap change (wait for operator to clean up extra data)
	return PollForConfigMapChange(client, cmCopy, "foo")
}

// DeletePod deletes a pod
func DeletePod(client kubernetes.Interface, name, namespace string) {
	err := client.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		fmt.Printf("failed to delete pod %s: %v\n", name, err)
	}
}

// PollForSecretChange polls for secret data to change
func PollForSecretChange(client kubernetes.Interface, secret *corev1.Secret, keysToChange ...string) error {
	return wait.PollImmediate(5*time.Second, 4*time.Minute, func() (bool, error) {
		s, err := client.CoreV1().Secrets(secret.Namespace).Get(context.TODO(), secret.Name, metav1.GetOptions{})
		if err != nil {
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

// PollForConfigMapChange polls for configmap data to change
func PollForConfigMapChange(client kubernetes.Interface, compareConfigMap *corev1.ConfigMap, keysToChange ...string) error {
	return wait.PollImmediate(5*time.Second, 4*time.Minute, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(compareConfigMap.Namespace).Get(context.TODO(), compareConfigMap.Name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		for _, key := range keysToChange {
			if cm.Data[key] == compareConfigMap.Data[key] {
				return false, nil
			}
		}
		return true, nil
	})
}
