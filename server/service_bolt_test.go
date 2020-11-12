package scepserver

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/boltdb/bolt"
	challengestore "github.com/micromdm/scep/challenge/bolt"
	boltdepot "github.com/micromdm/scep/depot/bolt"
	"github.com/micromdm/scep/scep"
	"github.com/pkg/errors"
)

type testSCEPSecrets struct {
	scepCert *x509.Certificate
	scepKey  *rsa.PrivateKey
}

func (tSCEPs *testSCEPSecrets) GetCACert() ([]*x509.Certificate, error) {
	return []*x509.Certificate{tSCEPs.scepCert}, nil
}

func (tSCEPs *testSCEPSecrets) GetCAKey(password []byte) (*rsa.PrivateKey, error) {
	return tSCEPs.scepKey, nil
}

type testCASecrets struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
}

func (tCAs *testCASecrets) SignCertificate(csr *x509.CertificateRequest) ([]byte, error) {
	id, err := GenerateSubjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-600).UTC(),
		NotAfter:     time.Now().AddDate(1, 0, 0).UTC(),
		SubjectKeyId: id,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
			x509.ExtKeyUsageClientAuth,
		},
	}
	crtBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tCAs.caCert, csr.PublicKey, tCAs.caKey)
	if err != nil {
		return nil, err
	}
	return crtBytes, nil
}
func TestDynamicChallenge(t *testing.T) {
	depot := createDB(0666, nil)
	caCert, caKey := loadCACredentials(t)
	tCAs := testCASecrets{caCert: caCert, caKey: caKey}
	tSCEPs := testSCEPSecrets{scepCert: caCert, scepKey: caKey}
	challengeDepot := createChallengeStore(0666, nil)
	opts := []ServiceOption{
		ClientValidity(365),
		WithDynamicChallenges(challengeDepot),
	}
	svc, err := NewService(depot, &tCAs, &tSCEPs, opts...)
	if err != nil {
		t.Fatal(err)
	}

	challenger := svc.(interface {
		SCEPChallenge() (string, error)
	})
	challenge, err := challenger.SCEPChallenge()
	if err != nil {
		t.Fatal(err)
	}

	impl := svc.(*service)
	if !impl.challengePasswordMatch(challenge) {
		t.Errorf("challenge password does not match")
	}
	if impl.challengePasswordMatch(challenge) {
		t.Errorf("challenge password matched but should only be used once")
	}

}

func TestCaCert(t *testing.T) {
	depot := createDB(0666, nil)
	caCert, caKey := loadCACredentials(t)
	tCAs := testCASecrets{caCert: caCert, caKey: caKey}
	tSCEPs := testSCEPSecrets{scepCert: caCert, scepKey: caKey}
	cacertBytes := caCert.Raw

	opts := []ServiceOption{
		ClientValidity(365),
	}
	svc, err := NewService(depot, &tCAs, &tSCEPs, opts...)
	if err != nil {
		t.Fatal(err)
	}

	selfKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	csrBytes, err := newCSR(selfKey, "ou", "loc", "province", "country", "cname", "org")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatal(err)
	}

	signerCert, err := selfSign(selfKey, csr)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		caBytes, num, err := svc.GetCACert(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if have, want := num, 1; have != want {
			t.Errorf("i=%d, have %d, want %d", i, have, want)
		}

		if have, want := caBytes, cacertBytes; !bytes.Equal(have, want) {
			t.Errorf("i=%d, have %v, want %v", i, have, want)
		}

		// create cert
		tmpl := &scep.PKIMessage{
			MessageType: scep.PKCSReq,
			Recipients:  []*x509.Certificate{caCert},
			SignerKey:   selfKey,
			SignerCert:  signerCert,
		}

		msg, err := scep.NewCSRRequest(csr, tmpl)
		if err != nil {
			t.Fatal(err)
		}

		_, err = svc.PKIOperation(ctx, msg.Raw)
		if err != nil {
			t.Fatal(err)
		}

	}

}

func createDB(mode os.FileMode, options *bolt.Options) *boltdepot.Depot {
	// Create temporary path.
	f, _ := ioutil.TempFile("", "bolt-")
	f.Close()
	os.Remove(f.Name())

	db, err := bolt.Open(f.Name(), mode, options)
	if err != nil {
		panic(err.Error())
	}
	d, err := boltdepot.NewBoltDepot(db)
	if err != nil {
		panic(err.Error())
	}
	return d
}

func createChallengeStore(mode os.FileMode, options *bolt.Options) *challengestore.Depot {
	// Create temporary path.
	f, _ := ioutil.TempFile("", "bolt-challenge-")
	f.Close()
	os.Remove(f.Name())

	db, err := bolt.Open(f.Name(), mode, options)
	if err != nil {
		panic(err.Error())
	}
	d, err := challengestore.NewBoltDepot(db)
	if err != nil {
		panic(err.Error())
	}
	return d
}

func newCSR(priv *rsa.PrivateKey, ou string, locality string, province string, country string, cname, org string) ([]byte, error) {
	subj := pkix.Name{
		CommonName: cname,
	}
	if len(org) > 0 {
		subj.Organization = []string{org}
	}
	if len(ou) > 0 {
		subj.OrganizationalUnit = []string{ou}
	}
	if len(province) > 0 {
		subj.Province = []string{province}
	}
	if len(locality) > 0 {
		subj.Locality = []string{locality}
	}
	if len(country) > 0 {
		subj.Country = []string{country}
	}
	template := &x509.CertificateRequest{
		Subject: subj,
	}
	return x509.CreateCertificateRequest(rand.Reader, template, priv)
}

func selfSign(priv *rsa.PrivateKey, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 1)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "SCEP SIGNER",
			Organization: csr.Subject.Organization,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

func loadCACredentials(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	cert, err := loadCertFromFile("../scep/testdata/testca/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	key, err := loadKeyFromFile("../scep/testdata/testca/ca.key")
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func loadCertFromFile(path string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != certificatePEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}
	return x509.ParseCertificate(pemBlock.Bytes)
}

// load an encrypted private key from disk
func loadKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != rsaPrivateKeyPEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	// testca key has a password
	if len(pemBlock.Headers) > 0 {
		password := []byte("")
		b, err := x509.DecryptPEMBlock(pemBlock, password)
		if err != nil {
			return nil, err
		}
		return x509.ParsePKCS1PrivateKey(b)
	}

	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)

}

func GenerateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	var pubBytes []byte
	var err error
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("only RSA public key is supported")
	}

	hash := sha1.Sum(pubBytes)

	return hash[:], nil
}
