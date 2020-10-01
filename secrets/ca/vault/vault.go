package vault

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/api"
)

type vaultSecrets struct {
	client   *api.Client
	roleID   string
	secretID string
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

func NewVaultSecrets(address string, roleID string, secretID string) (*vaultSecrets, error) {
	client, err := api.NewClient(&api.Config{Address: address, HttpClient: &http.Client{}})
	if err != nil {
		return nil, err
	}

	err = Login(client, roleID, secretID)
	if err != nil {
		return nil, err
	}
	return &vaultSecrets{client: client, roleID: roleID, secretID: secretID}, nil
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
	signPath := "ca1/sign/ca1"
	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	options := map[string]interface{}{
		"csr":         string(csrBytes),
		"common_name": csr.Subject.CommonName,
	}
	data, err := vs.client.Logical().Write(signPath, options)
	if err != nil {
		return nil, err
	}
	certData := data.Data["certificate"]
	fmt.Println(certData.(string))
	certPEMBlock, _ := pem.Decode([]byte(certData.(string)))
	if certPEMBlock == nil || certPEMBlock.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}
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
