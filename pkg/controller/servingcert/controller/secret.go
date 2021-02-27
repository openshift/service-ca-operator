package controller

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"

	ocontroller "github.com/openshift/library-go/pkg/controller"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

func namespacedObjToQueueKey(obj runtime.Object) string {
	metaObj := obj.(metav1.Object)
	return fmt.Sprintf("%s/%s", metaObj.GetNamespace(), metaObj.GetName())
}

func objFromQueueKey(qKey string) (string, string) {
	nsName := strings.SplitN(qKey, "/", 2)
	return nsName[0], nsName[1]
}

func secretFromSecretEventObj(obj interface{}) *corev1.Secret {
	secret, secretOK := obj.(*corev1.Secret)
	if !secretOK {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return nil
		}

		secret, secretOK = tombstone.Obj.(*corev1.Secret)
		if !secretOK {
			return nil
		}
	}
	return secret
}

// Returns true if the secret certificate certKey was issued by the current CA,
// false if not or if there was a parsing error.
//
// Determination of issuance will default to comparison of the certificate's
// AuthorityKeyID and the CA's SubjectKeyId, and fall back to comparison of the
// certificate's Issuer.CommonName and the CA's Subject.CommonName (in case the CA was
// generated prior to the addition of key identifiers).
func secretIsIssuedByCA(secret *corev1.Secret, certKey string, servingCA *ServingCA) bool {
	certs, err := cert.ParseCertsPEM(secret.Data[certKey])
	if err != nil {
		klog.V(4).Infof("warning: error parsing certificate data in %s/%s during issuer check: %v",
			secret.Namespace, secret.Name, err)
		return false
	}

	if len(certs) == 0 || certs[0] == nil {
		klog.V(4).Infof("warning: no certs returned from ParseCertsPEM during issuer check")
		return false
	}

	certAuthorityKeyId := certs[0].AuthorityKeyId
	caSubjectKeyId := servingCA.ca.Config.Certs[0].SubjectKeyId
	// Use key identifier chaining if the SubjectKeyId is populated in the CA
	// certificate. AuthorityKeyId may not be set in the serving certificate if it was
	// generated before serving cert generation was updated to include the field.
	if len(caSubjectKeyId) > 0 {
		return bytes.Equal(certAuthorityKeyId, caSubjectKeyId)
	}

	// Fall back to name-based chaining for a legacy service CA that was generated
	// without SubjectKeyId or AuthorityKeyId.
	return certs[0].Issuer.CommonName == servingCA.commonName()
}

// secretRequiresRegeneration returns true if the secret is not owned by ownedRef or expires within minTimeLeft,
// defaulting to true on error.
func secretRequiresRegeneration(secret *v1.Secret, ownerRef metav1.OwnerReference, minTimeLeft time.Duration) bool {
	// if we don't have an ownerref, just go ahead and regenerate.  It's easier than writing a
	// secondary logic flow.
	if !ocontroller.HasOwnerRef(secret, ownerRef) {
		return true
	}
	// if we don't have the annotation for expiry, just go ahead and regenerate.  It's easier than writing a
	// secondary logic flow that creates the expiry dates
	expiryString, ok := secret.Annotations[api.ServingCertExpiryAnnotation]
	if !ok {
		expiryString, ok = secret.Annotations[api.AlphaServingCertExpiryAnnotation]
		if !ok {
			return true
		}
	}
	expiry, err := time.Parse(time.RFC3339, expiryString)
	if err != nil {
		return true
	}

	if time.Now().Add(minTimeLeft).After(expiry) {
		return true
	}

	return false
}
