package client

import (
	"context"
	"crypto/x509"
)

type Client interface {
	StartRemoteClient(ctx context.Context, CA string) error
	GetCertificate(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error)
}
