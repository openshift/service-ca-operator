package controller

import (
	"crypto/x509"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/service-ca-operator/pkg/controller/servingcert/cryptoextensions"
)

// ServingCA is the CA managed by the service-ca controller process.
type ServingCA struct {
	ca                 *crypto.CA
	intermediateCACert *x509.Certificate
	dnsSuffix          string
}

// NewServingCA returns a ServingCA based on its raw components.
func NewServingCA(
	ca *crypto.CA,
	intermediateCACert *x509.Certificate,
	dnsSuffix string,
) *ServingCA {
	return &ServingCA{
		ca:                 ca,
		intermediateCACert: intermediateCACert,
		dnsSuffix:          dnsSuffix,
	}
}

func (sca *ServingCA) commonName() string {
	return sca.ca.Config.Certs[0].Subject.CommonName
}

// makeServingCert generates a TLS certificate + private key for dnsName, optionally adding
// the cryptoextensions.OpenShiftServerSigningServiceUIDOID for serviceUID if it is not nil.
func (sca *ServingCA) makeServingCert(dnsName string, serviceUID *types.UID) (*crypto.TLSCertificateConfig, error) {
	fqDNSName := dnsName + "." + sca.dnsSuffix
	certificateLifetime := 365 * 2 // 2 years
	fns := []crypto.CertificateExtensionFunc{}
	if serviceUID != nil {
		fns = append(fns, cryptoextensions.ServiceServerCertificateExtensionV1(*serviceUID))
	}
	servingCert, err := sca.ca.MakeServerCert(
		sets.NewString(dnsName, fqDNSName),
		certificateLifetime,
		fns...,
	)
	if err != nil {
		return nil, err
	}

	// Including the intermediate cert will ensure that clients with a
	// stale ca bundle (containing the previous CA but not the current
	// one) will be able to trust the serving cert.
	if sca.intermediateCACert != nil {
		servingCert.Certs = append(servingCert.Certs, sca.intermediateCACert)
	}

	return servingCert, nil
}
