package file

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

type file struct {
	Info os.FileInfo
	Data []byte
}

type fileSCEPSecrets struct {
	dirPath string
}

func NewFileSCEPSecrets(path string) (*fileSCEPSecrets, error) {
	return &fileSCEPSecrets{dirPath: path}, nil
}

func (d *fileSCEPSecrets) GetCACert() ([]*x509.Certificate, error) {
	caPEM, err := d.getFile("ca.pem")
	if err != nil {
		return nil, err
	}
	cert, err := loadCert(caPEM.Data)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

func (d *fileSCEPSecrets) GetCAKey() (*rsa.PrivateKey, error) {
	keyPEM, err := d.getFile("ca.key")
	if err != nil {
		return nil, err
	}

	key, err := loadKey(keyPEM.Data, nil)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (d *fileSCEPSecrets) GetCAKeyPassword() []byte {
	return []byte("dummy_password")
}

func (d *fileSCEPSecrets) getFile(path string) (*file, error) {
	if err := d.check(path); err != nil {
		return nil, err
	}
	fi, err := os.Stat(d.path(path))
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(d.path(path))
	return &file{fi, b}, err
}

func (d *fileSCEPSecrets) path(name string) string {
	return filepath.Join(d.dirPath, name)
}

func (d *fileSCEPSecrets) check(path string) error {
	name := d.path(path)
	_, err := os.Stat(name)
	if err != nil {
		return err
	}
	return nil
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

//load an encrypted private key from disk
func loadKey(data []byte, password []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}

	if pemBlock.Type != rsaPrivateKeyPEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}

//load an encrypted private key from disk
func loadCert(data []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != certificatePEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	return x509.ParseCertificate(pemBlock.Bytes)
}
