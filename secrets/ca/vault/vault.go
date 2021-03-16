package vault

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/hashicorp/vault/api"
)

type vaultSecrets struct {
	client   *api.Client
	roleID   string
	secretID string
	CA       string
	logger   log.Logger
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

func NewVaultSecrets(address string, roleID string, secretID string, CA string, CACert string, logger log.Logger) (*vaultSecrets, error) {
	conf := api.DefaultConfig()
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", address)
	tlsConf := &api.TLSConfig{CACert: CACert}
	conf.ConfigureTLS(tlsConf)
	client, err := api.NewClient(conf)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not create Vault API client")
		return nil, err
	}

	err = Login(client, roleID, secretID)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not login into Vault")
		return nil, err
	}
	return &vaultSecrets{client: client, roleID: roleID, secretID: secretID, CA: CA, logger: logger}, nil
}

func Login(client *api.Client, roleID string, secretID string) error {
	loginPath := "auth/approle/login"
	options := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	resp, err := client.Logical().Write(loginPath, options)
	if err != nil {
		return err
	}
	client.SetToken(resp.Auth.ClientToken)
	return nil
}

func (vs *vaultSecrets) SignCertificate(csr *x509.CertificateRequest) ([]byte, error) {
	signPath := vs.CA + "/sign/enroller"
	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	options := map[string]interface{}{
		"csr":         string(csrBytes),
		"common_name": csr.Subject.CommonName,
	}
	data, err := vs.client.Logical().Write(signPath, options)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Vault could not sign certificate")
		return nil, err
	}
	certData := data.Data["certificate"]
	certPEMBlock, _ := pem.Decode([]byte(certData.(string)))
	if certPEMBlock == nil || certPEMBlock.Type != "CERTIFICATE" {
		err = errors.New("Failed to decode PEM block containing certificate")
		level.Error(vs.logger).Log("err", err)
		return nil, err
	}
	level.Info(vs.logger).Log("msg", "Vault returned certificate signed")
	return certPEMBlock.Bytes, nil

}

// load a certicate from vault
func loadCert(data string) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode([]byte(data))
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != certificatePEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	return x509.ParseCertificate(pemBlock.Bytes)
}

// load private key from vault
func loadKey(data string) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode([]byte(data))
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != rsaPrivateKeyPEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}
	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}
