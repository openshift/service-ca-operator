package util

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		client.CoreV1().Namespaces().Delete(context.TODO(), ns.Name, metav1.DeleteOptions{})
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
