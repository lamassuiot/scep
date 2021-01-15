package file

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type file struct {
	Info os.FileInfo
	Data []byte
}

type fileSCEPSecrets struct {
	dirPath string
	logger  log.Logger
}

func NewFileSCEPSecrets(path string, logger log.Logger) (*fileSCEPSecrets, error) {
	return &fileSCEPSecrets{dirPath: path, logger: logger}, nil
}

func (d *fileSCEPSecrets) GetCACert() ([]*x509.Certificate, error) {
	caPEM, err := d.getFile("ca.pem")
	if err != nil {
		level.Error(d.logger).Log("err", err, "msg", "Could not obtain SCEP server certificate")
		return nil, err
	}
	cert, err := loadCert(caPEM.Data)
	if err != nil {
		level.Error(d.logger).Log("err", err, "msg", "Could not parse SCEP server certificate")
		return nil, err
	}
	level.Info(d.logger).Log("msg", "SCEP certificate loaded and parsed")
	return []*x509.Certificate{cert}, nil
}

func (d *fileSCEPSecrets) GetCAKey(password []byte) (*rsa.PrivateKey, error) {
	keyPEM, err := d.getFile("ca.key")
	if err != nil {
		level.Error(d.logger).Log("err", err, "msg", "Could not obtain SCEP key")
		return nil, err
	}
	key, err := loadKey(keyPEM.Data, password)
	if err != nil {
		level.Error(d.logger).Log("err", err, "msg", "Could not parse SCEP key")
		return nil, err
	}
	level.Info(d.logger).Log("msg", "SCEP key loaded and parsed")
	return key, nil
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

//load a private key from disk
func loadKey(data []byte, password []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}

	if pemBlock.Type != rsaPrivateKeyPEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}
	var pemBlockBytes []byte
	if len(password) > 0 && password != nil {
		pemBlockBytes, _ = x509.DecryptPEMBlock(pemBlock, password)
	} else {
		pemBlockBytes = pemBlock.Bytes
	}
	return x509.ParsePKCS1PrivateKey(pemBlockBytes)
}

//load a certifiate from disk
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
