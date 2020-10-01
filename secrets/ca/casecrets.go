package ca

import "crypto/x509"

type CASecrets interface {
	SignCertificate(csr *x509.CertificateRequest) ([]byte, error)
}
