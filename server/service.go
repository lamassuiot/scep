package scepserver

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/go-kit/kit/log"
	"github.com/micromdm/scep/challenge"
	"github.com/micromdm/scep/csrverifier"
	"github.com/micromdm/scep/depot"
	"github.com/micromdm/scep/scep"
	casecrets "github.com/micromdm/scep/secrets/ca"
	scepsecrets "github.com/micromdm/scep/secrets/scep"
)

// Service is the interface for all supported SCEP server operations.
type Service interface {
	// Checks server's health
	Health(ctx context.Context) bool

	// GetCACaps returns a list of options
	// which are supported by the server.
	GetCACaps(ctx context.Context) ([]byte, error)

	// GetCACert returns CA certificate or
	// a CA certificate chain with intermediates
	// in a PKCS#7 Degenerate Certificates format
	GetCACert(ctx context.Context) ([]byte, int, error)

	// PKIOperation handles incoming SCEP messages such as PKCSReq and
	// sends back a CertRep PKIMessag.
	PKIOperation(ctx context.Context, msg []byte) ([]byte, error)

	// GetNextCACert returns a replacement certificate or certificate chain
	// when the old one expires. The response format is a PKCS#7 Degenerate
	// Certificates type.
	GetNextCACert(ctx context.Context) ([]byte, error)
}

type service struct {
	depot                   depot.Depot
	caSecrets               casecrets.CASecrets
	scepSecrets             scepsecrets.SCEPSecrets
	ca                      []*x509.Certificate // CA cert or chain
	caKey                   *rsa.PrivateKey
	caKeyPassword           []byte
	csrTemplate             *x509.Certificate
	challengePassword       string
	supportDynamciChallenge bool
	dynamicChallengeStore   challenge.Store
	csrVerifier             csrverifier.CSRVerifier
	allowRenewal            int // days before expiry, 0 to disable
	clientValidity          int // client cert validity in days

	/// info logging is implemented in the service middleware layer.
	debugLogger log.Logger
}

// SCEPChallenge returns a brand new, random dynamic challenge.
func (svc *service) SCEPChallenge() (string, error) {
	if !svc.supportDynamciChallenge {
		return svc.challengePassword, nil
	}

	return svc.dynamicChallengeStore.SCEPChallenge()
}

func (svc *service) Health(ctx context.Context) bool {
	return true
}

func (svc *service) GetCACaps(ctx context.Context) ([]byte, error) {
	defaultCaps := []byte("Renewal\nSHA-1\nSHA-256\nAES\nDES3\nSCEPStandard\nPOSTPKIOperation")
	return defaultCaps, nil
}

// Vault API call to obtain CA cert
func (svc *service) GetCACert(ctx context.Context) ([]byte, int, error) {
	scepCA, err := svc.scepSecrets.GetCACert()
	if len(scepCA) == 0 {
		return nil, 0, err
	}
	if len(scepCA) == 1 {
		return scepCA[0].Raw, 1, nil
	}
	data, err := scep.DegenerateCertificates(scepCA)
	return data, len(svc.ca), err
}

func (svc *service) PKIOperation(ctx context.Context, data []byte) ([]byte, error) {
	msg, err := scep.ParsePKIMessage(data, scep.WithLogger(svc.debugLogger))
	if err != nil {
		return nil, err
	}
	scepCA, err := svc.scepSecrets.GetCACert()
	if err != nil {
		return nil, errors.New("unable to get SCEP CA Cert")
	}
	scepCAKey, err := svc.scepSecrets.GetCAKey(svc.caKeyPassword)
	if err != nil {
		return nil, errors.New("unable to get CA Key")
	}
	if err := msg.DecryptPKIEnvelope(scepCA[0], scepCAKey); err != nil {
		return nil, err
	}

	// validate challenge passwords
	if msg.MessageType == scep.PKCSReq {
		CSRIsValid := false

		if svc.csrVerifier != nil {
			result, err := svc.csrVerifier.Verify(msg.CSRReqMessage.RawDecrypted)
			if err != nil {
				return nil, err
			}
			CSRIsValid = result
			if !CSRIsValid {
				svc.debugLogger.Log("err", "CSR is not valid")
			}
		} else {
			CSRIsValid = svc.challengePasswordMatch(msg.CSRReqMessage.ChallengePassword)
			if !CSRIsValid {
				svc.debugLogger.Log("err", "scep challenge password does not match")
			}
		}

		if !CSRIsValid {
			certRep, err := msg.Fail(scepCA[0], scepCAKey, scep.BadRequest)
			if err != nil {
				return nil, err
			}
			return certRep.Raw, nil
		}
	}

	csr := msg.CSRReqMessage.CSR

	//Change this method to sign CSR with Vault CA
	certRep, err := msg.SignCSR(scepCA[0], scepCAKey, csr, svc.caSecrets)
	if err != nil {
		return nil, err
	}

	crt := certRep.CertRepMessage.Certificate
	name := certName(crt)

	// Test if this certificate is already in the CADB, revoke if needed
	// revocation is done if the validity of the existing certificate is
	// less than allowRenewal (14 days by default)
	_, err = svc.depot.HasCN(name, svc.allowRenewal, crt, false)
	if err != nil {
		return nil, err
	}

	if err := svc.depot.Put(name, crt); err != nil {
		return nil, err
	}

	return certRep.Raw, nil
}

func certName(crt *x509.Certificate) string {
	if crt.Subject.CommonName != "" {
		return crt.Subject.CommonName
	}
	return string(crt.Signature)
}

func (svc *service) GetNextCACert(ctx context.Context) ([]byte, error) {
	panic("not implemented")
}

func (svc *service) challengePasswordMatch(pw string) bool {
	if svc.challengePassword == "" && !svc.supportDynamciChallenge {
		// empty password, don't validate
		return true
	}
	if !svc.supportDynamciChallenge && svc.challengePassword == pw {
		return true
	}

	if svc.supportDynamciChallenge {
		valid, err := svc.dynamicChallengeStore.HasChallenge(pw)
		if err != nil {
			svc.debugLogger.Log(err)
			return false
		}
		return valid
	}

	return false
}

// ServiceOption is a server configuration option
type ServiceOption func(*service) error

// WithCSRVerifier is an option argument to NewService
// which allows setting a CSR verifier.
func WithCSRVerifier(csrVerifier csrverifier.CSRVerifier) ServiceOption {
	return func(s *service) error {
		s.csrVerifier = csrVerifier
		return nil
	}
}

// ChallengePassword is an optional argument to NewService
// which allows setting a preshared key for SCEP.
func ChallengePassword(pw string) ServiceOption {
	return func(s *service) error {
		s.challengePassword = pw
		return nil
	}
}

// CAKeyPassword is an optional argument to NewService for
// specifying the CA private key password.
func CAKeyPassword(pw []byte) ServiceOption {
	return func(s *service) error {
		s.caKeyPassword = pw
		return nil
	}
}

// allowRenewal sets the days before expiry which we are allowed to renew (optional)
func AllowRenewal(duration int) ServiceOption {
	return func(s *service) error {
		s.allowRenewal = duration
		return nil
	}
}

// ClientValidity sets the validity of signed client certs in days (optional parameter)
func ClientValidity(duration int) ServiceOption {
	return func(s *service) error {
		s.clientValidity = duration
		return nil
	}
}

// WithLogger configures a logger for the SCEP Service.
// By default, a no-op logger is used.
func WithLogger(logger log.Logger) ServiceOption {
	return func(s *service) error {
		s.debugLogger = logger
		return nil
	}
}

func WithDynamicChallenges(cache challenge.Store) ServiceOption {
	return func(s *service) error {
		s.supportDynamciChallenge = true
		s.dynamicChallengeStore = cache
		return nil
	}
}

// NewService creates a new scep service
func NewService(depot depot.Depot, caSecrets casecrets.CASecrets, scepSecrets scepsecrets.SCEPSecrets, opts ...ServiceOption) (Service, error) {
	s := &service{
		depot:       depot,
		caSecrets:   caSecrets,
		scepSecrets: scepSecrets,
		debugLogger: log.NewNopLogger(),
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

// GenerateSubjectKeyID generates SubjectKeyId used in Certificate
// ID is 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
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
