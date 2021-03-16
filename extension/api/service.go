package api

import (
	"context"
	"errors"
	"sync"

	"github.com/micromdm/scep/extension/client"
	"github.com/micromdm/scep/extension/utils"
)

type Service interface {
	Health(ctx context.Context) bool
	PostSetConfig(ctx context.Context, CA string) error
	PostGetCRT(ctx context.Context, csrData []byte) (crtData []byte, err error)
}

type deviceService struct {
	mtx    sync.RWMutex
	client client.Client
}

func NewDeviceService(client client.Client) Service {
	return &deviceService{client: client}
}

var (
	//Client errors
	errUnableParseCSR = errors.New("unable to parse CSR raw bytes")

	//Server errors
	errRemoteConnection = errors.New("unable to start remote connection")
)

func (s *deviceService) Health(ctx context.Context) bool {
	return true
}

func (s *deviceService) PostSetConfig(ctx context.Context, CA string) error {
	err := s.client.StartRemoteClient(ctx, CA)
	if err != nil {
		return errRemoteConnection
	}
	return nil
}

func (s *deviceService) PostGetCRT(ctx context.Context, csrData []byte) (crtData []byte, err error) {
	csr, err := utils.ParseNewCSR(csrData)
	if err != nil {
		return nil, errUnableParseCSR
	}
	crt, err := s.client.GetCertificate(ctx, csr)
	if err != nil {
		return nil, err
	}
	return utils.PEMCert(crt.Raw), nil
}
