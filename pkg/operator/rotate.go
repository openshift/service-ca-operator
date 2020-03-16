package operator

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/klog"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/operator/util"
)

const (
	// The minimum remaining duration of the service CA needs to exceeds the maximum
	// supported upgrade interval (currently 12 months). A duration of 26 months
	// (rotated at 13 months) ensures that an upgrade will occur after automated
	// rotation and before the expiry of the pre-rotation CA. Since an upgrade restarts
	// all services, those services will always be using valid material.
	//
	// Example timeline using a 26 month service CA duration:
	//
	// - T+0m  - Cluster installed with new CA or existing CA is rotated (CA-1)
	// - T+12m - Cluster is upgraded and all pods are restarted
	// - T+13m - Automated rotation replaces CA-1 with CA-2 when CA-1 duration < 13m
	// - T+24m - Cluster is upgraded and all pods are restarted
	// - T+26m - CA-1 expires. No impact because of the restart at time of upgrade
	//
	SigningCertificateLifetimeInDays = 790 // 26 months

	// The minimum duration that a CA should be trusted is approximately half
	// the default signing certificate lifetime. If a signing CA is valid for
	// less than this duration, it is due for rotation. An intermediate
	// certificate created by rotation (to ensure that the previous CA remains
	// trusted) should be valid for at least this long.
	minimumTrustDuration = 395 * 24 * time.Hour // 13 months
)

type signingCA struct {
	config             *crypto.TLSCertificateConfig
	bundle             []*x509.Certificate
	intermediateCACert *x509.Certificate
	oldCAExpiry        time.Time
}

// updateSigningSecret updates the provided secret with the signing artifacts.
func (ca *signingCA) updateSigningSecret(secret *corev1.Secret) error {
	caPEM, keyPEM, err := ca.config.GetPEMBytes()
	if err != nil {
		return err
	}
	bundlePEM, err := crypto.EncodeCertificates(ca.bundle...)
	if err != nil {
		return err
	}
	intermediatePEM, err := crypto.EncodeCertificates(ca.intermediateCACert)
	if err != nil {
		return err
	}

	d := secret.Data
	d[corev1.TLSCertKey] = caPEM
	d[corev1.TLSPrivateKeyKey] = keyPEM
	d[api.BundleDataKey] = bundlePEM
	d[api.IntermediateDataKey] = intermediatePEM

	return nil
}

// maybeRotateSigningSecret rotates the CA of the given signing secret if required.
//
// On successful rotation, the secret will be updated with the data of the new CA and a
// non-empty rotation message will be returned.  Rotation will not be performed if the
// current CA is not more than half-way expired or if a forced rotation was not
// requested, and in this case an empty rotation message will be returned.
func maybeRotateSigningSecret(secret *corev1.Secret, currentCACert *x509.Certificate, serviceCAConfig unsupportedServiceCAConfig) (string, error) {
	reason := serviceCAConfig.ForceRotation.Reason
	forcedRotation := forcedRotationRequired(secret, reason)

	minimumExpiry := time.Now().Add(minimumTrustDuration)
	timeBasedRotation := currentCACert.NotAfter.Before(minimumExpiry)

	if !(forcedRotation || timeBasedRotation) {
		return "", nil
	}

	if forcedRotation {
		klog.V(2).Infof("Forcing service CA rotation due to reason %q.", reason)
		recordForcedRotationReason(secret, reason)
	} else {
		klog.V(2).Infof("Rotating service CA due to the CA being past the mid-point of its validity.")
	}

	keyData := secret.Data[corev1.TLSPrivateKeyKey]
	if len(keyData) == 0 {
		return "", fmt.Errorf("signing secret is missing a value for %q", corev1.TLSPrivateKeyKey)
	}
	key, err := keyutil.ParsePrivateKeyPEM(keyData)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key from PEM: %v", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("expected RSA private key, got %T", key)
	}

	signingCA, err := rotateSigningCA(currentCACert, rsaKey)
	if err != nil {
		return "", err
	}

	// Set a custom expiry for testing if one was provided
	signingCA.config, err = maybeUpdateExpiry(signingCA.config, serviceCAConfig.CAConfig.ValidityDurationForTesting)
	if err != nil {
		return "", fmt.Errorf("failed to renew ca for custom duration: %v", err)
	}

	err = signingCA.updateSigningSecret(secret)
	if err != nil {
		return "", err
	}

	oldCAExpiry := signingCA.oldCAExpiry.Format(time.RFC3339)
	rotationMsg := fmt.Sprintf("CA rotation complete. The previous CA will be trusted until %s", oldCAExpiry)
	return rotationMsg, nil
}

// rotateSigningCA creates a new signing CA, bundle and intermediate CA that together can
// be used to ensure that serving certs generated both before and after rotation can be
// trusted by both refreshed and unrefreshed consumers.
func rotateSigningCA(currentCACert *x509.Certificate, currentKey *rsa.PrivateKey) (*signingCA, error) {
	// Generate a new signing cert
	newCAConfig, err := crypto.MakeSelfSignedCAConfigForSubject(currentCACert.Subject, SigningCertificateLifetimeInDays)
	if err != nil {
		return nil, err
	}
	newCACert := newCAConfig.Certs[0]

	// Ensure that the intermediate cert bridging trust between the current and new CAs
	// has an expiry that guarantees a minimum trust duration.
	var currentCACertExpiry *time.Time
	minimumExpiry := time.Now().Add(minimumTrustDuration)
	if currentCACert.NotAfter.Before(minimumExpiry) {
		currentCACertExpiry = &minimumExpiry
	}

	// Generate an intermediate cert bridging trust between the new CA and serving certs
	// generated by the current CA for inclusion in the new CA bundle. This will ensure
	// that clients with a post-rotation ca bundle will be able to trust pre-rotation
	// serving certs.
	currentCACertSignedByNewCA, err := createIntermediateCACert(currentCACert, newCACert, newCAConfig.Key.(*rsa.PrivateKey), currentCACertExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate certificate signed by new ca: %v", err)
	}

	bundle := []*x509.Certificate{
		newCACert,
		currentCACertSignedByNewCA,
	}

	// Generate an intermediate cert bridging trust between the current CA and serving
	// certs generated by the new CA. This cert will need to be included with serving
	// certs generated by the new CA to ensure that clients with the pre-rotation ca
	// bundle will be able to trust post-rotation serving certs.
	newCACertSignedByOldCA, err := createIntermediateCACert(newCACert, currentCACert, currentKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate certificate signed by previous ca: %v", err)
	}

	return &signingCA{
		config:             newCAConfig,
		bundle:             bundle,
		intermediateCACert: newCACertSignedByOldCA,
		oldCAExpiry:        currentCACertSignedByNewCA.NotAfter,
	}, nil
}

// createIntermediateCACert creates a new intermediate CA cert from a template provided by
// the target CA cert and issued by the signing cert. This ensures that certificates
// issued by the target CA can be trusted by clients that trust the signing CA.
func createIntermediateCACert(targetCACert, signingCACert *x509.Certificate, signingKey *rsa.PrivateKey, expiry *time.Time) (*x509.Certificate, error) {
	// Copy the target cert to allow modification.
	template, err := x509.ParseCertificate(targetCACert.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to copy ca certificate: %v", err)
	}
	// Enable key identity chaining
	template.AuthorityKeyId = signingCACert.SubjectKeyId

	// Set a new serial number so that the intermediate CA cert is
	// differentiated from the target CA cert. This ensures that a serving
	// cert bundle that includes the issuing CA cert and an intermediate CA
	// cert generated by this function - with the issuing CA cert as the
	// target and the previous CA as the signer - will not result in
	// SEC_ERROR_REUSED_ISSUER_AND_SERIAL when read by applications like curl.
	serialGenerator := crypto.RandomSerialGenerator{}
	serial, err := serialGenerator.Next(template)
	if err != nil {
		return nil, fmt.Errorf("failed to find next serial number: %v", err)
	}
	template.SerialNumber = big.NewInt(serial)

	// Update the expiry if necessary
	if expiry != nil {
		template.NotAfter = *expiry
	}

	caCert, err := util.CreateCertificate(template, signingCACert, targetCACert.PublicKey, signingKey)
	if err != nil {
		return nil, fmt.Errorf("error creating intermediate CA certificate: %v", err)
	}

	return caCert, nil
}

// forcedRotationRequired indicates whether the force rotation reason is not empty and
// does not match the annotation stored on the signing secret.
func forcedRotationRequired(secret *corev1.Secret, reason string) bool {
	if len(reason) == 0 {
		return false
	}
	seenReason := secret.Annotations[api.ForcedRotationReasonAnnotationName]
	return reason != seenReason
}

// recordForcedRotationReason annotates the signing secret with the reason for performing
// a forced rotation.
func recordForcedRotationReason(secret *corev1.Secret, reason string) {
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations[api.ForcedRotationReasonAnnotationName] = reason
}
