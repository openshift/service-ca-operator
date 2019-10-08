package operator

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/google/uuid"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/service-ca-operator/pkg/controller/servingcert/controller"
	"github.com/openshift/service-ca-operator/test/util"
)

// TestRotateSigningCA validates that service certs signed by pre- and
// post-rotation CAs can be validated by both pre- and post-rotation
// old bundles.
func TestRotateSigningCA(t *testing.T) {
	// Used in generating serving certs
	dnsSuffix := "local"
	objMeta := &metav1.ObjectMeta{
		Name:      "myservice",
		Namespace: "mynamespace",
		UID:       types.UID(uuid.New().String()),
	}

	oldCAConfig, err := crypto.MakeSelfSignedCAConfig("foo", signingCertificateLifetimeInDays)
	if err != nil {
		t.Fatalf("error generating a new ca: %v", err)
	}
	oldCA := &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          oldCAConfig,
	}
	oldBundlePEM, err := crypto.EncodeCertificates(oldCAConfig.Certs[0])
	if err != nil {
		t.Fatalf("error encoding old bundle to PEM: %v", err)
	}

	// Generate a service cert with the pre-rotation CA
	oldServingCert, err := controller.GetServingCert(dnsSuffix, oldCA, nil, objMeta)
	if err != nil {
		t.Fatalf("error generating serving cert from old ca: %v", err)
	}
	oldCertPEM, oldKeyPEM, err := oldServingCert.GetPEMBytes()
	if err != nil {
		t.Fatalf("error encoding old serving cert to PEM: %v", err)
	}

	// Simulate forced rotation by renewing the current ca with a
	// validity bounds more than half-way expired. This is required
	// for e2e testing, and performing it here ensures that unit
	// testing is as similar as possible so that testing can be more
	// cheaply maintained.
	notBefore := time.Now().Add(-3 * time.Hour)
	notAfter := time.Now().Add(1 * time.Hour)
	renewedCAConfig, err := util.RenewSelfSignedCertificate(oldCAConfig, notBefore, notAfter)
	if err != nil {
		t.Fatalf("error renewing ca to half-expired form: %v", err)
	}

	// Rotate the CA
	newSigningCA, err := rotateSigningCA(renewedCAConfig.Certs[0], renewedCAConfig.Key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatalf("Error rotating signing ca: %v", err)
	}
	newCA := &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          newSigningCA.config,
	}
	newBundlePEM, err := crypto.EncodeCertificates(newSigningCA.bundle...)

	// Generate a service cert with the post-rotation CA
	newServingCert, err := controller.GetServingCert(dnsSuffix, newCA, newSigningCA.intermediateCACert, objMeta)
	if err != nil {
		t.Fatalf("Error generating new service cert: %v", err)
	}
	newCertPEM, newKeyPEM, err := newServingCert.GetPEMBytes()
	if err != nil {
		t.Fatalf("Error encoding new serving cert to PEM: %v", err)
	}

	// The AuthorityKeyId of the serving cert should match the CA cert's SubjectKeyId so
	// that when these values differ (i.e. when the CA is next rotated), the serving
	// cert controller will know to regenerate the serving cert.
	if bytes.Compare(newServingCert.Certs[0].AuthorityKeyId, newSigningCA.config.Certs[0].SubjectKeyId) != 0 {
		t.Fatalf("The AuthorityKeyId of the serving cert does not match the SubjectKeyId of the CA cert")
	}

	dnsName := oldServingCert.Certs[0].Subject.CommonName
	util.CheckRotation(t, dnsName, oldCertPEM, oldKeyPEM, oldBundlePEM, newCertPEM, newKeyPEM, newBundlePEM)
}

func TestCertHalfwayExpired(t *testing.T) {
	now := time.Now()
	tests := map[string]struct {
		testCert *x509.Certificate
		expected bool
	}{
		"expired now": {
			testCert: &x509.Certificate{
				NotBefore: now.AddDate(0, 0, -1),
				NotAfter:  now,
			},
			expected: true,
		},
		"time left": {
			testCert: &x509.Certificate{
				NotBefore: now.AddDate(0, 0, -1),
				NotAfter:  now.AddDate(0, 0, 2),
			},
			expected: false,
		},
		"time up": {
			testCert: &x509.Certificate{
				NotBefore: now.AddDate(0, 0, -2),
				NotAfter:  now.AddDate(0, 0, 1),
			},
			expected: true,
		},
	}
	for name, tc := range tests {
		if certHalfwayExpired(tc.testCert) != tc.expected {
			t.Errorf("%s: unexpected result, expected %v, got %v", name, tc.expected, !tc.expected)
		}
	}
}
