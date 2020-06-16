package vault

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
	return &vaultSecrets{client: client, roleID: roleID, secretID: secretID}, nil
}

func (vs *vaultSecrets) Login() error {
	loginPath := "auth/approle/login"
	options := map[string]interface{}{
		"role_id":   vs.roleID,
		"secret_id": vs.secretID,
	}
	resp, err := vs.client.Logical().Write(loginPath, options)
	if err != nil {
		return err
	}
	vs.client.SetToken(resp.Auth.ClientToken)
	return nil
}

func (vs *vaultSecrets) GetSecret(secretKey string) (*x509.Certificate, *rsa.PrivateKey, error) {
	secretPath := "kv/" + secretKey
	data, err := vs.client.Logical().Read(secretPath)
	if err != nil {
		return nil, nil, err
	}
	keyData := data.Data["key"]
	certData := data.Data["cert"]
	cert, err := loadCert(certData.(string))
	if err != nil {
		return nil, nil, err
	}
	key, err := loadKey(keyData.(string))
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil

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
