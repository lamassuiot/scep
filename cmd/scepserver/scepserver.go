package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/micromdm/scep/csrverifier"
	executablecsrverifier "github.com/micromdm/scep/csrverifier/executable"
	"github.com/micromdm/scep/depot"
	"github.com/micromdm/scep/depot/relational"
	"github.com/micromdm/scep/discovery/consul"
	scepserver "github.com/micromdm/scep/server"

	casecrets "github.com/micromdm/scep/secrets/ca"
	"github.com/micromdm/scep/secrets/ca/vault"

	scepsecrets "github.com/micromdm/scep/secrets/scep"
	"github.com/micromdm/scep/secrets/scep/file"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"

	jaegercfg "github.com/uber/jaeger-client-go/config"
)

// version info
var (
	version = "unreleased"
	gitHash = "unknown"
)

func main() {
	var caCMD = flag.NewFlagSet("ca", flag.ExitOnError)
	{
		if len(os.Args) >= 2 {
			if os.Args[1] == "ca" {
				status := caMain(caCMD)
				os.Exit(status)
			}
		}
	}

	//main flags
	var (
		flVersion           = flag.Bool("version", false, "prints version information")
		flHost              = flag.String("host", envString("SCEP_HOST", "scep"), "host where service is started")
		flPort              = flag.String("port", envString("SCEP_HTTP_LISTEN_PORT", "8080"), "port to listen on")
		flDepotPath         = flag.String("depot", envString("SCEP_FILE_DEPOT", "depot"), "path to ca folder")
		flCAPass            = flag.String("capass", envString("SCEP_CA_PASS", ""), "password for the ca.key")
		flVaultAddress      = flag.String("vaultaddress", envString("SCEP_VAULT_ADDRESS", "vault"), "vault address")
		flVaultCA           = flag.String("vaultca", envString("SCEP_VAULT_CA", "Lamassu-Root-CA1-RSA4096"), "vault CA")
		flRoleID            = flag.String("roleid", envString("SCEP_ROLE_ID", ""), "vault RoleID")
		flSecretID          = flag.String("secretid", envString("SCEP_SECRET_ID", ""), "vault SecretID")
		flHomePath          = flag.String("homepath", envString("SCEP_HOME_PATH", ""), "home path")
		flDBName            = flag.String("dbname", envString("SCEP_DB_NAME", "ca_store"), "DB name")
		flDBUser            = flag.String("dbuser", envString("SCEP_DB_USER", "scep"), "DB user")
		flDBPassword        = flag.String("dbpass", envString("SCEP_DB_PASSWORD", ""), "DB password")
		flDBHost            = flag.String("dbhost", envString("SCEP_DB_HOST", ""), "DB host")
		flDBPort            = flag.String("dbport", envString("SCEP_DB_PORT", ""), "DB port")
		flConsulProtocol    = flag.String("consulprotocol", envString("SCEP_CONSULPROTOCOL", ""), "Consul server protocol")
		flConsulHost        = flag.String("consulhost", envString("SCEP_CONSULHOST", ""), "Consul host")
		flConsulPort        = flag.String("consulport", envString("SCEP_CONSULPORT", ""), "Consul port")
		flConsulCA          = flag.String("consulca", envString("SCEP_CONSULCA", ""), "Consul CA path")
		flProxyHost         = flag.String("proxyhost", envString("SCEP_PROXYHOST", "scepproxy"), "server proxy hostname")
		flProxyPort         = flag.String("proxyport", envString("SCEP_PROXYPORT", "8088"), "server proxy port")
		flClDuration        = flag.String("crtvalid", envString("SCEP_CERT_VALID", "365"), "validity for new client certificates in days")
		flClAllowRenewal    = flag.String("allowrenew", envString("SCEP_CERT_RENEW", "14"), "do not allow renewal until n days before expiry, set to 0 to always allow")
		flChallengePassword = flag.String("challenge", envString("SCEP_CHALLENGE_PASSWORD", ""), "enforce a challenge password")
		flCSRVerifierExec   = flag.String("csrverifierexec", envString("SCEP_CSR_VERIFIER_EXEC", ""), "will be passed the CSRs for verification")
		flDebug             = flag.Bool("debug", envBool("SCEP_LOG_DEBUG"), "enable debug logging")
		flLogJSON           = flag.Bool("log-json", envBool("SCEP_LOG_JSON"), "output JSON logs")
	)
	flag.Usage = func() {
		flag.PrintDefaults()

		fmt.Println("usage: scep [<command>] [<args>]")
		fmt.Println(" ca <args> create/manage a CA")
		fmt.Println("type <command> --help to see usage for each subcommand")
	}
	flag.Parse()

	// print version information
	if *flVersion {
		fmt.Printf("scep - %v\n", version)
		fmt.Printf("git revision - %v\n", gitHash)
		os.Exit(0)
	}
	port := ":" + *flPort

	var logger log.Logger
	{

		if *flLogJSON {
			logger = log.NewJSONLogger(os.Stdout)
		} else {
			logger = log.NewLogfmtLogger(os.Stdout)
		}
		if !*flDebug {
			logger = level.NewFilter(logger, level.AllowInfo())
		}
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}
	lginfo := level.Info(logger)

	var err error

	var caSecrets casecrets.CASecrets
	{
		caSecrets, err = vault.NewVaultSecrets(*flVaultAddress, *flRoleID, *flSecretID, *flVaultCA, lginfo)
		if err != nil {
			level.Error(lginfo).Log("err", err, "msg", "Could not start connection with CA Vault Secret Engine")
			os.Exit(1)
		}
	}
	level.Info(lginfo).Log("msg", "Connection established with CA secret engine")

	var scepSecrets scepsecrets.SCEPSecrets
	{
		scepSecrets, err = file.NewFileSCEPSecrets(*flDepotPath, logger)
		if err != nil {
			level.Error(lginfo).Log("err", err, "msg", "Could not start SCEP File secret engine")
			os.Exit(1)
		}
	}
	level.Info(lginfo).Log("msg", "Connection established with SCEP secret engine")

	var depot depot.Depot // cert storage
	{
		//depot, err = file.NewFileDepot(*flDepotPath)
		connStr := "dbname=" + *flDBName + " user=" + *flDBUser + " password=" + *flDBPassword + " host=" + *flDBHost + " port=" + *flDBPort + " sslmode=disable"
		depot, err = relational.NewRelationalDepot("postgres", connStr, *flHomePath, logger)
		if err != nil {
			level.Error(lginfo).Log("err", err, "msg", "Could not start connection with signed certificates database")
			os.Exit(1)
		}
	}
	level.Info(lginfo).Log("msg", "Connection established with signed certificates database")

	allowRenewal, err := strconv.Atoi(*flClAllowRenewal)
	if err != nil {
		level.Error(lginfo).Log("err", err, "msg", "No valid number for allowed renewal time")
		os.Exit(1)
	}
	clientValidity, err := strconv.Atoi(*flClDuration)
	if err != nil {
		level.Error(lginfo).Log("err", err, "msg", "No valid number for client cert validity")
		os.Exit(1)
	}
	var csrVerifier csrverifier.CSRVerifier
	if *flCSRVerifierExec > "" {
		executableCSRVerifier, err := executablecsrverifier.New(*flCSRVerifierExec, lginfo)
		if err != nil {
			level.Error(lginfo).Log("err", err, "msg", "Could not instantiate CSR verifier")
			os.Exit(1)
		}
		csrVerifier = executableCSRVerifier
	}

	jcfg, err := jaegercfg.FromEnv()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not load Jaeger configuration values fron environment")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Jaeger configuration values loaded")
	tracer, closer, err := jcfg.NewTracer()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Jaeger tracer")
		os.Exit(1)
	}
	defer closer.Close()
	level.Info(logger).Log("msg", "Jaeger tracer started")

	fieldKeys := []string{"method", "error"}

	var svc scepserver.Service // scep service
	{
		svcOptions := []scepserver.ServiceOption{
			scepserver.ChallengePassword(*flChallengePassword),
			scepserver.WithCSRVerifier(csrVerifier),
			scepserver.CAKeyPassword([]byte(*flCAPass)),
			scepserver.ClientValidity(clientValidity),
			scepserver.AllowRenewal(allowRenewal),
			scepserver.WithLogger(logger),
		}
		svc, err = scepserver.NewService(depot, caSecrets, scepSecrets, svcOptions...)
		if err != nil {
			level.Error(lginfo).Log("err", err, "msg", "Could not instantiate SCEP service")
			os.Exit(1)
		}
		svc = scepserver.NewLoggingService(log.With(lginfo, "component", "scep_service"), svc)
		svc = scepserver.NewInstrumentingMiddleware(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "scep_server",
				Subsystem: "service",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "scep_server",
				Subsystem: "service",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
			svc)
	}

	consulsd, err := consul.NewServiceDiscovery(*flConsulProtocol, *flConsulHost, *flConsulPort, *flProxyHost, *flProxyPort, *flConsulCA, logger)
	if err != nil {
		level.Error(lginfo).Log("err", err, "msg", "Could not start connection with Consul Service Discovery")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Connection established with Consul Service Discovery")
	err = consulsd.Register("http", *flHost, *flPort)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not register service liveness information to Consul")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Service liveness information registered to Consul")
	var h http.Handler // http handler
	{
		e := scepserver.MakeServerEndpoints(svc, tracer)
		e.GetEndpoint = scepserver.EndpointLoggingMiddleware(lginfo)(e.GetEndpoint)
		e.PostEndpoint = scepserver.EndpointLoggingMiddleware(lginfo)(e.PostEndpoint)
		h = scepserver.MakeHTTPHandler(e, svc, log.With(lginfo, "component", "http"), tracer)
	}

	// start http server
	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	go func() {
		level.Info(lginfo).Log("transport", "HTTP", "address", *flHost+":"+*flPort, "msg", "listening")
		errs <- http.ListenAndServe(port, h)
	}()

	level.Info(lginfo).Log("exit", <-errs)
	err = consulsd.Deregister()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not deregister service liveness information from Consul")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Service liveness information deregistered from Consul")
}

func caMain(cmd *flag.FlagSet) int {
	var (
		flDepotPath = cmd.String("depot", "depot", "path to ca folder")
		flInit      = cmd.Bool("init", false, "create a new CA")
		flYears     = cmd.Int("years", 10, "default CA years")
		flKeySize   = cmd.Int("keySize", 4096, "rsa key size")
		flOrg       = cmd.String("organization", "scep-ca", "organization for CA cert")
		flOrgUnit   = cmd.String("organizational_unit", "SCEP CA", "organizational unit (OU) for CA cert")
		flPassword  = cmd.String("key-password", "", "password to store rsa key")
		flCountry   = cmd.String("country", "US", "country for CA cert")
	)
	cmd.Parse(os.Args[2:])
	if *flInit {
		fmt.Println("Initializing new CA")
		key, err := createKey(*flKeySize, []byte(*flPassword), *flDepotPath)
		if err != nil {
			fmt.Println(err)
			return 1
		}
		if err := createCertificateAuthority(key, *flYears, *flOrg, *flOrgUnit, *flCountry, *flDepotPath); err != nil {
			fmt.Println(err)
			return 1
		}
	}

	return 0
}

// create a key, save it to depot and return it for further usage.
func createKey(bits int, password []byte, depot string) (*rsa.PrivateKey, error) {
	// create depot folder if missing
	if err := os.MkdirAll(depot, 0755); err != nil {
		return nil, err
	}
	name := filepath.Join(depot, "ca.key")
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// create RSA key and save as PEM file
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	privPEMBlock, err := x509.EncryptPEMBlock(
		rand.Reader,
		rsaPrivateKeyPEMBlockType,
		x509.MarshalPKCS1PrivateKey(key),
		password,
		x509.PEMCipher3DES,
	)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(file, privPEMBlock); err != nil {
		os.Remove(name)
		return nil, err
	}

	return key, nil
}

func createCertificateAuthority(key *rsa.PrivateKey, years int, organization string, organizationalUnit string, country string, depot string) error {
	var (
		authPkixName = pkix.Name{
			Country:            nil,
			Organization:       nil,
			OrganizationalUnit: nil,
			Locality:           nil,
			Province:           nil,
			StreetAddress:      nil,
			PostalCode:         nil,
			SerialNumber:       "",
			CommonName:         "",
		}
		// Build CA based on RFC5280
		authTemplate = x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      authPkixName,
			// NotBefore is set to be 10min earlier to fix gap on time difference in cluster
			NotBefore: time.Now().Add(-600).UTC(),
			NotAfter:  time.Time{},
			// Used for certificate signing only
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

			ExtKeyUsage:        nil,
			UnknownExtKeyUsage: nil,

			// activate CA
			BasicConstraintsValid: true,
			IsCA:                  true,
			// Not allow any non-self-issued intermediate CA
			MaxPathLen: 0,

			// 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
			// (excluding the tag, length, and number of unused bits)
			// **SHOULD** be filled in later
			SubjectKeyId: nil,

			// Subject Alternative Name
			DNSNames: nil,

			PermittedDNSDomainsCritical: false,
			PermittedDNSDomains:         nil,
		}
	)

	subjectKeyID, err := generateSubjectKeyID(&key.PublicKey)
	if err != nil {
		return err
	}
	authTemplate.SubjectKeyId = subjectKeyID
	authTemplate.NotAfter = time.Now().AddDate(years, 0, 0).UTC()
	authTemplate.Subject.Country = []string{country}
	authTemplate.Subject.Organization = []string{organization}
	authTemplate.Subject.OrganizationalUnit = []string{organizationalUnit}
	crtBytes, err := x509.CreateCertificate(rand.Reader, &authTemplate, &authTemplate, &key.PublicKey, key)
	if err != nil {
		return err
	}

	name := filepath.Join(depot, "ca.pem")
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(pemCert(crtBytes)); err != nil {
		file.Close()
		os.Remove(name)
		return err
	}

	return nil
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

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

func pemCert(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    certificatePEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}

func envString(key, def string) string {
	if env := os.Getenv(key); env != "" {
		return env
	}
	return def
}

func envBool(key string) bool {
	if env := os.Getenv(key); env == "true" {
		return true
	}
	return false
}
