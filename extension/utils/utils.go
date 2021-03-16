package utils

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

const (
	CertPEMBlockType = "CERTIFICATE"
	CSRPEMBlockType  = "CERTIFICATE REQUEST"
	KeyPEMBlockType  = "RSA PRIVATE KEY"
)

func ParseNewCSR(data []byte) (*x509.CertificateRequest, error) {
	pemBlock, _ := pem.Decode(data)
	err := CheckPEMBlock(pemBlock, CSRPEMBlockType)
	if err != nil {
		return nil, err
	}
	certReq, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return certReq, nil
}

func CheckPEMBlock(pemBlock *pem.Block, blockType string) error {
	if pemBlock == nil {
		return errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != blockType || len(pemBlock.Headers) != 0 {
		return errors.New("unmatched type of headers")
	}
	return nil
}

func PEMCert(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    CertPEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}

func CreateCAPool(CAPath string) (*x509.CertPool, error) {
	caCert, err := ioutil.ReadFile(CAPath)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return caCertPool, nil
}
