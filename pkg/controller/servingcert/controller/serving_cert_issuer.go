package controller

import (
	"crypto/x509"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"

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
	// When configurable PKI is enabled, attempt to resolve a certificate
	// config from the PKI profile. A nil config (Unmanaged mode) means
	// no custom key configuration is active, so fall through to the
	// legacy code path.
	if s.configurablePKIEnabled {
		var certificateConfig *pki.CertificateConfig
		certificateConfig, err = pki.ResolveCertificateConfig(s.pkiProvider, pki.CertificateTypeServing, "service-ca.service-serving")
		// TODO: This NotFound fallback may be temporary while ConfigurablePKI
		// is in tech preview. Once the installer provides the initial "cluster"
		// PKI resource, this fallback may no longer be needed.
		if apierrors.IsNotFound(err) {
			klog.V(2).Infof("PKI resource not found, using default PKI profile")
			defaultProfile := pki.DefaultPKIProfile()
			defaultProvider := pki.NewStaticPKIProfileProvider(&defaultProfile)
			certificateConfig, err = pki.ResolveCertificateConfig(defaultProvider, pki.CertificateTypeServing, "service-ca.service-serving")
		}
		if err != nil {
			return nil, fmt.Errorf("failed to resolve PKI certificate config: %w", err)
		}
		if certificateConfig != nil {
			servingCert, err = s.ca.NewServerCertificate(subjects, certificateConfig.Key,
				crypto.WithLifetime(s.certificateLifetime),
				crypto.WithExtensions(cryptoextensions.ServiceServerCertificateExtensionV1(service.UID)),
			)
			if err != nil {
				return nil, err
			}
		}
	}
	// Fall back to legacy cert generation when configurable PKI is
	// disabled or the PKI profile is Unmanaged (nil config).
	if servingCert == nil {
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
