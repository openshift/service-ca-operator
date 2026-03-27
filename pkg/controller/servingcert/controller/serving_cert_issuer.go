package controller

import (
	"crypto/x509"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/openshift/library-go/pkg/controller"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/pki"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/controller/servingcert/cryptoextensions"
)

// servingCertIssuer holds the CA, PKI config, and methods for generating
// serving certificates. It is embedded by both the creating and updating
// controllers.
type servingCertIssuer struct {
	ca                  *crypto.CA
	intermediateCACert  *x509.Certificate
	dnsSuffix           string
	certificateLifetime time.Duration

	configurablePKIEnabled bool
	pkiProvider            pki.PKIProfileProvider
}

// makeServingCert generates a TLS serving certificate for the given service.
func (s *servingCertIssuer) makeServingCert(service *corev1.Service) (*crypto.TLSCertificateConfig, error) {
	subjects := certSubjectsForService(service, s.dnsSuffix)
	var servingCert *crypto.TLSCertificateConfig
	var err error
	if s.configurablePKIEnabled {
		var certificateConfig *pki.CertificateConfig
		certificateConfig, err = pki.ResolveCertificateConfig(s.pkiProvider, pki.CertificateTypeServing, "service-ca.service-serving")
		if err != nil {
			return nil, fmt.Errorf("failed to resolve PKI certificate config: %w", err)
		}
		servingCert, err = s.ca.NewServerCertificate(subjects, certificateConfig.Key,
			crypto.WithLifetime(s.certificateLifetime),
			crypto.WithExtensions(cryptoextensions.ServiceServerCertificateExtensionV1(service.UID)),
		)
	} else {
		servingCert, err = s.ca.MakeServerCert(
			subjects,
			s.certificateLifetime,
			cryptoextensions.ServiceServerCertificateExtensionV1(service.UID),
		)
	}
	if err != nil {
		return nil, err
	}

	// Including the intermediate cert will ensure that clients with a
	// stale ca bundle (containing the previous CA but not the current
	// one) will be able to trust the serving cert.
	if s.intermediateCACert != nil {
		servingCert.Certs = append(servingCert.Certs, s.intermediateCACert)
	}

	return servingCert, nil
}

// toRequiredSecret populates the given secret with a newly generated serving
// certificate for the service.
func (s *servingCertIssuer) toRequiredSecret(service *corev1.Service, secretCopy *corev1.Secret) error {
	servingCert, err := s.makeServingCert(service)
	if err != nil {
		return err
	}
	certBytes, keyBytes, err := servingCert.GetPEMBytes()
	if err != nil {
		return err
	}
	if secretCopy.Annotations == nil {
		secretCopy.Annotations = map[string]string{}
	}
	// let garbage collector cleanup map allocation, for simplicity
	secretCopy.Data = map[string][]byte{
		corev1.TLSCertKey:       certBytes,
		corev1.TLSPrivateKeyKey: keyBytes,
	}

	secretCopy.Annotations[api.AlphaServingCertExpiryAnnotation] = servingCert.Certs[0].NotAfter.Format(time.RFC3339)
	secretCopy.Annotations[api.ServingCertExpiryAnnotation] = servingCert.Certs[0].NotAfter.Format(time.RFC3339)

	controller.EnsureOwnerRef(secretCopy, ownerRef(service))

	return nil
}

// MakeServingCert generates a TLS serving certificate using the legacy code path used by the operator tests.
func MakeServingCert(dnsSuffix string, ca *crypto.CA, intermediateCACert *x509.Certificate, service *corev1.Service, lifetime time.Duration) (*crypto.TLSCertificateConfig, error) {
	return (&servingCertIssuer{
		ca:                  ca,
		intermediateCACert:  intermediateCACert,
		dnsSuffix:           dnsSuffix,
		certificateLifetime: lifetime,
	}).makeServingCert(service)
}
