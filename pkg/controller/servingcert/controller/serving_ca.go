package controller

import (
	"crypto/x509"

	"github.com/openshift/library-go/pkg/crypto"
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
