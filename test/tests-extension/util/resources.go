package util

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// CreateTestNamespace creates a test namespace
func CreateTestNamespace(client kubernetes.Interface, namespaceName string) (*corev1.Namespace, func(), error) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
	}
	ns, err := client.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		// best-effort delete + wait for termination
		_ = client.CoreV1().Namespaces().Delete(context.TODO(), ns.Name, metav1.DeleteOptions{})
		// Block until the namespace is fully gone to avoid name collisions
		// (ignore errors after timeout to avoid hanging teardown).
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		wait.PollImmediateUntil(2*time.Second, func() (bool, error) {
			_, err := client.CoreV1().Namespaces().Get(context.TODO(), ns.Name, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, nil
		}, ctx.Done())
	}
	return ns, cleanup, err
}

// CreateServingCertAnnotatedService creates a service with serving cert annotation
func CreateServingCertAnnotatedService(client kubernetes.Interface, secretName, serviceName, namespace string, headless bool) error {
	service := &corev1.Service{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
			Annotations: map[string]string{
				ServingCertSecretAnnotation: secretName,
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "tests",
					Port: 8443,
				},
			},
		},
	}
	if headless {
		service.Spec.Selector = map[string]string{
			"owning-headless-service": serviceName,
		}
		service.Spec.ClusterIP = corev1.ClusterIPNone
	}
	_, err := client.CoreV1().Services(namespace).Create(context.TODO(), service, metav1.CreateOptions{})
	return err
}

// CreateAnnotatedCABundleInjectionConfigMap creates a configmap with CA bundle injection annotation
func CreateAnnotatedCABundleInjectionConfigMap(client kubernetes.Interface, configMapName, namespace string) error {
	obj := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: configMapName,
		},
	}
	SetInjectionAnnotation(&obj.ObjectMeta)
	_, err := client.CoreV1().ConfigMaps(namespace).Create(context.TODO(), obj, metav1.CreateOptions{})
	return err
}

// SetInjectionAnnotation sets the annotation that will trigger the injection of a ca bundle.
func SetInjectionAnnotation(objMeta *metav1.ObjectMeta) {
	if objMeta.Annotations == nil {
		objMeta.Annotations = map[string]string{}
	}
	objMeta.Annotations[InjectCABundleAnnotationName] = "true"
}
