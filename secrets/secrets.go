package secrets

import (
	"crypto/rsa"
	"crypto/x509"
)

type Secrets interface {
	Login() error
	GetSecret(secretKey string) (*x509.Certificate, *rsa.PrivateKey, error)
}
