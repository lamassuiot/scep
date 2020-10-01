package scep

import (
	"crypto/rsa"
	"crypto/x509"
)

type SCEPSecrets interface {
	GetCACert() ([]*x509.Certificate, error)
	GetCAKey() (*rsa.PrivateKey, error)
	GetCAKeyPassword() []byte
}
