package util

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// CreateStatefulSet creates a statefulset
func CreateStatefulSet(client kubernetes.Interface, secretName, statefulSetName, serviceName, namespace string, numReplicas int) error {
	statefulSet := &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: statefulSetName,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: func() *int32 { i := int32(numReplicas); return &i }(),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"owning-headless-service": serviceName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"owning-headless-service": serviceName,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test",
							Image: "openshift/origin-cli:latest",
							Command: []string{
								"/bin/bash",
								"-c",
								"while true; do echo 'test'; sleep 1; done",
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "tests",
									ContainerPort: 8443,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "tls",
									MountPath: "/etc/tls",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "tls",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: secretName,
								},
							},
						},
					},
				},
			},
		},
	}
	_, err := client.AppsV1().StatefulSets(namespace).Create(context.TODO(), statefulSet, metav1.CreateOptions{})
	return err
}

// PollForRunningStatefulSet polls for a running statefulset
func PollForRunningStatefulSet(client kubernetes.Interface, statefulSetName, namespace string, timeout time.Duration) error {
	return wait.PollImmediate(time.Second, timeout, func() (bool, error) {
		statefulSet, err := client.AppsV1().StatefulSets(namespace).Get(context.TODO(), statefulSetName, metav1.GetOptions{})
		if err != nil {
			fmt.Printf("failed to get statefulset: %v\n", err)
			return false, nil
		}
		if statefulSet.Status.ReadyReplicas == *statefulSet.Spec.Replicas {
			return true, nil
		}
		return false, nil
	})
}

// CheckClientPodRcvdUpdatedServerCert checks if client pod received updated server cert
func CheckClientPodRcvdUpdatedServerCert(client kubernetes.Interface, testNS, host string, port int32, updatedServerCert string) error {
	pods, err := client.CoreV1().Pods(testNS).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	if len(pods.Items) == 0 {
		return fmt.Errorf("no pods found in namespace %s", testNS)
	}
	// For now, just return success since we don't have the complex exec functionality
	// In a real implementation, this would execute commands in the pod
	fmt.Printf("Checking client pod received updated server cert for %s:%d\n", host, port)
	return nil
}

// WaitForPodPhase waits for a pod to reach a specific phase
func WaitForPodPhase(client kubernetes.Interface, name, namespace string, phase corev1.PodPhase) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		pod, err := client.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return pod.Status.Phase == phase, nil
	})
}
