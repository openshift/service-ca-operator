package controller

import (
	"fmt"
	"math"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openshift/library-go/pkg/controller"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

const (
	// statefulSetExtraCerts is the minimum number of certificates created on top of the StatefulSet’s
	// Spec.Replicas , so that scaling the StatefulSet does not immediately cause failures because
	// certificates for the new pods are not available.
	// This should always be greater than zero to ensure the api.AlphaServingCertExpiryAnnotation value
	// is well-defined.
	// The greater of statefulSetExtraCertFactor and Spec.Replicas * statefulSetExtraCertFactor applies.
	statefulSetExtraCerts = 5
	// statefulSetExtraCertFactor is multiplied by StatefulSet’s Spec.Replicas to obtain a minimum
	// number of certificates created on top of Spec.Replicas , so that scaling the StatefulSet does
	// not immediately cause failures because certificates for the new pods are not available.
	// The greater of statefulSetExtraCertFactor and Spec.Replicas * statefulSetExtraCertFactor applies.
	statefulSetExtraCertFactor = 0.3
)

func toStatefulSetName(secret *v1.Secret) (string, bool) {
	statefulSetName := secret.Annotations[api.AlphaStatefulSetNameAnnotation]
	return statefulSetName, len(statefulSetName) != 0
}

func statefulSetFromSecretEventObj(obj interface{}) (string, bool) {
	secret := secretFromSecretEventObj(obj)
	if secret == nil {
		return "", false
	}
	return toStatefulSetName(secret)
}

func statefulSetFromSecretQueueFunc(obj runtime.Object) string {
	ssName, _ := statefulSetFromSecretEventObj(obj)
	metaObj := obj.(metav1.Object)
	return fmt.Sprintf("%s/%s", metaObj.GetNamespace(), ssName)
}

func secretsStatefulSetNameQueueFilter(obj interface{}) bool {
	_, ok := statefulSetFromSecretEventObj(obj)
	return ok
}

func statefulSetOwnerRef(statefulSet *appsv1.StatefulSet) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: appsv1.SchemeGroupVersion.String(),
		Kind:       "StatefulSet",
		Name:       statefulSet.Name,
		UID:        statefulSet.UID,
	}
}

// desiredCertsForStatefulSetSecret returns the number of certificates we want to have
// in a StatefulSet-related secret.
func desiredCertsForStatefulSetSecret(statefulSet *appsv1.StatefulSet) int {
	replicas := int32(1) // The default value of Spec.Replicas, sadly seems not to be a Go constant in the API
	if statefulSet.Spec.Replicas != nil {
		replicas = *statefulSet.Spec.Replicas
	}

	added := int(replicas) + statefulSetExtraCerts
	multiplied := math.Min(math.Ceil(float64(replicas)*statefulSetExtraCertFactor), math.MaxInt32)
	multInt := int(multiplied)
	if added > multInt {
		return added
	}
	return multInt
}

// statefulSetCertKeyFilenames returns names of the (certificate, key) items we want to maintain in a secret.
func statefulSetCertKeyFilenames(index int) (string, string) {
	prefix := fmt.Sprintf("%d", index)
	return prefix + ".crt", prefix + ".key"
}

// statefulSetSecretCount returns the number of currently existing items in a secret
// (going purely by file names, without validating contents)
func statefulSetSecretCount(sharedSecret *corev1.Secret) int {
	for res := 0; ; res++ {
		certName, keyName := statefulSetCertKeyFilenames(res)
		if _, ok := sharedSecret.Data[certName]; !ok {
			return res
		}
		if _, ok := sharedSecret.Data[keyName]; !ok {
			return res
		}
	}
}

func regenerateStatefulSetSecret(servingCA *ServingCA, statefulSet *appsv1.StatefulSet, secretCopy *corev1.Secret) error {
	if secretCopy.Annotations == nil {
		secretCopy.Annotations = map[string]string{}
	}

	// For simplicity, this regenerates all certificates every time, even if most of them
	// were available and far from expiration (and in the worst case we only need to generate
	// one more to keep pace with an added replica).  We may want to revisit that if certificate
	// generation performace becomes a concern.
	var minExpiry *time.Time
	secretCopy.Data = map[string][]byte{} // let garbage collector cleanup map allocation, for simplicity
	total := desiredCertsForStatefulSetSecret(statefulSet)
	for index := 0; index < total; index++ {
		dnsName := fmt.Sprintf("%s-%d.%s.%s.svc",
			statefulSet.Name, index,
			statefulSet.Spec.ServiceName, statefulSet.Namespace)
		// NOTE: Unlike service secrets, we don’t include the
		// cryptoextensions.OpenShiftServerSigningServiceUIDOID extension because it is defined
		// to contain a service UID; eventually we could define a new extension for StatefulSet
		// (or generic?) UIDs.
		servingCert, err := servingCA.makeServingCert(dnsName, nil)
		if err != nil {
			return err
		}

		certBytes, keyBytes, err := servingCert.GetPEMBytes()
		if err != nil {
			return err
		}
		certName, keyName := statefulSetCertKeyFilenames(index)
		secretCopy.Data[certName] = certBytes
		secretCopy.Data[keyName] = keyBytes

		certExpiry := servingCert.Certs[0].NotAfter
		if minExpiry == nil || minExpiry.After(certExpiry) {
			minExpiry = &certExpiry
		}
	}

	if minExpiry == nil {
		return fmt.Errorf("can't set %s annotation on %s/%s: no minExpiry value computed from %d certificates",
			api.AlphaServingCertExpiryAnnotation, secretCopy.Namespace, secretCopy.Name, total)
	}
	secretCopy.Annotations[api.AlphaServingCertExpiryAnnotation] = minExpiry.Format(time.RFC3339)

	controller.EnsureOwnerRef(secretCopy, statefulSetOwnerRef(statefulSet))

	return nil
}
