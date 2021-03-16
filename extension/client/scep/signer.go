package scep

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/micromdm/scep/extension/utils"
)

func loadSignerInfo(certFile string, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cert, err := loadSignerCert(certFile)
	if err != nil {
		return nil, nil, err
	}
	key, err := loadSignerKey(keyFile)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func loadSignerKey(keyFile string) (*rsa.PrivateKey, error) {
	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(keyPEM)
	err = utils.CheckPEMBlock(pemBlock, utils.KeyPEMBlockType)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil

}

func loadSignerCert(certFile string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(certPEM)
	err = utils.CheckPEMBlock(pemBlock, utils.CertPEMBlockType)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
