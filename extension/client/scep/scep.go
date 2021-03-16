package scep

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/hashicorp/consul/api"

	consulsd "github.com/go-kit/kit/sd/consul"
	scepclient "github.com/micromdm/scep/client"
	"github.com/micromdm/scep/extension/client"
	"github.com/micromdm/scep/scep"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type SCEP struct {
	keyFile        string
	certFile       string
	serverPort     string
	consulProtocol string
	consulHost     string
	consulPort     string
	consulCA       string
	SCEPMapping    map[string]string
	remote         scepclient.Client
	logger         log.Logger
	otTracer       stdopentracing.Tracer
}

var (
	ErrSignerInfoLoading = errors.New("unable to read Signer info")
	ErrCSRCreate         = errors.New("unable to create CSR")
	ErrCSRRequestCreate  = errors.New("unable to create CSR request")
	ErrDecryptPKI        = errors.New("unable to decrypt PKI message")
	ErrGetRemoteCA       = errors.New("error getting remote CA certificate")
	ErrRemoteConnection  = errors.New("error connecting to remote server")
	ErrConsulConnection  = errors.New("error connecting to Service Discovery server")
)

func NewClient(certFile string, keyFile string, serverPort string, consulProtocol string, consulHost string, consulPort string, consulCA string, SCEPMapping map[string]string, logger log.Logger, otTracer stdopentracing.Tracer) client.Client {
	return &SCEP{
		certFile:       certFile,
		keyFile:        keyFile,
		serverPort:     serverPort,
		consulProtocol: consulProtocol,
		consulHost:     consulHost,
		consulPort:     consulPort,
		consulCA:       consulCA,
		SCEPMapping:    SCEPMapping,
		logger:         logger,
		otTracer:       otTracer,
	}
}

func (s *SCEP) StartRemoteClient(ctx context.Context, CA string) error {
	serverURL := "http://" + s.SCEPMapping[CA] + ":" + s.serverPort

	consulConfig := api.DefaultConfig()
	consulConfig.Address = s.consulProtocol + "://" + s.consulHost + ":" + s.consulPort
	tlsConf := &api.TLSConfig{CAFile: s.consulCA}
	consulConfig.TLSConfig = *tlsConf
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "Could not start Consul API Client")
		return ErrConsulConnection
	}
	clientConsul := consulsd.NewClient(consulClient)
	tags := []string{"scep", s.SCEPMapping[CA]}
	passingOnly := true
	duration := 500 * time.Millisecond
	instancer := consulsd.NewInstancer(clientConsul, s.logger, s.SCEPMapping[CA], tags, passingOnly)

	scepClient, err := scepclient.NewSD(serverURL, duration, instancer, s.logger, s.otTracer)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "Could not start SCEP Server Client")
		return err
	}
	level.Info(s.logger).Log("msg", "SCEP Client started")
	s.remote = scepClient
	level.Info(s.logger).Log("msg", "SCEP Server Client started")
	_, err = s.remote.GetCACaps(ctx)
	if err != nil {
		level.Error(s.logger)
		return ErrRemoteConnection
	}
	level.Info(s.logger).Log("msg", "SCEP Server CA capabilities succesfully obtained")
	return nil
}

func (s *SCEP) GetCertificate(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	sigCert, sigKey, err := loadSignerInfo(s.certFile, s.keyFile)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "Could not load SCEP request signer information")
		return nil, err
	}
	resp, certNum, err := s.remote.GetCACert(ctx)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "Could not get CA certificate from SCEP Server")
		return nil, ErrGetRemoteCA
	}

	var certs []*x509.Certificate
	{
		if certNum > 1 {
			certs, err = scep.CACerts(resp)
			if err != nil {
				level.Error(s.logger).Log("err", err, "msg", "Could not get CA certificate from SCEP Server")
				return nil, ErrGetRemoteCA
			}
			if len(certs) < 1 {
				level.Error(s.logger).Log("err", err, "msg", "Could not get CA certificate from SCEP Server")
				return nil, ErrGetRemoteCA
			}
		} else {
			certs, err = x509.ParseCertificates(resp)
			if err != nil {
				level.Error(s.logger).Log("err", err, "msg", "Could not parse CA certificate obtained from SCEP Server")
				return nil, ErrGetRemoteCA
			}
		}
	}
	level.Info(s.logger).Log("msg", "CA certificate obtained from SCEP Server")

	var msgType scep.MessageType
	{
		msgType = scep.PKCSReq
	}

	tmpl := &scep.PKIMessage{
		MessageType: msgType,
		Recipients:  certs,
		SignerKey:   sigKey,
		SignerCert:  sigCert,
	}

	msg, err := scep.NewCSRRequest(csr, tmpl)
	if err != nil {
		level.Error(s.logger).Log("err", err, "msg", "Could not create CSR Request SCEP message")
		return nil, ErrCSRRequestCreate
	}
	level.Info(s.logger).Log("msg", "SCEP CSR Request message created")

	var respMsg *scep.PKIMessage

	for {
		// loop in case we get a PENDING response which requires
		// a manual approval.

		respBytes, err := s.remote.PKIOperation(ctx, msg.Raw)
		if err != nil {
			level.Error(s.logger).Log("err", err, "msg", "Could not perform PKI operation")
			return nil, err
		}

		respMsg, err = scep.ParsePKIMessage(respBytes)
		if err != nil {
			level.Error(s.logger).Log("err", err, "msg", "Could not parse PKI message")
			return nil, err
		}

		switch respMsg.PKIStatus {
		case scep.FAILURE:
			err = encodeSCEPFailure(respMsg.FailInfo)
			level.Error(s.logger).Log("err", err, "msg", "PKI operation failed")
			return nil, err
		case scep.PENDING:
			time.Sleep(30 * time.Second)
			continue
		}
		break // on scep.SUCCESS
	}
	level.Info(s.logger).Log("msg", "PKI operation performed successfully")

	if err := respMsg.DecryptPKIEnvelope(sigCert, sigKey); err != nil {
		level.Error(s.logger).Log("err", err, "msg", "Could not decrypt PKI envelope")
		return nil, ErrDecryptPKI
	}
	respCert := respMsg.CertRepMessage.Certificate
	level.Info(s.logger).Log("msg", "PKI envelope decrypted and certificate obtained")
	return respCert, nil
}

func encodeSCEPFailure(fi scep.FailInfo) error {
	switch fi {
	case scep.BadAlg:
		return errors.New("bad algorithm from remote server")
	case scep.BadMessageCheck:
		return errors.New("bad message check from remote server")
	case scep.BadRequest:
		return errors.New("bad request from remote server")
	case scep.BadTime:
		return errors.New("bad time from remote server")
	case scep.BadCertID:
		return errors.New("bad cert ID from remote server")
	default:
		return errors.New("bad request from remote server")
	}
	return nil
}
