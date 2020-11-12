package scepclient

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	scepserver "github.com/micromdm/scep/server"
)

// Client is a SCEP Client
type Client interface {
	scepserver.Service
	Supports(cap string) bool
}

// New creates a SCEP Client.
func New(serverURL string, logger log.Logger, httpc *http.Client) (Client, error) {
	endpoints, err := scepserver.MakeClientEndpoints(serverURL, httpc)
	if err != nil {
		return nil, err
	}
	logger = level.Info(logger)
	endpoints.GetEndpoint = scepserver.EndpointLoggingMiddleware(logger)(endpoints.GetEndpoint)
	endpoints.PostEndpoint = scepserver.EndpointLoggingMiddleware(logger)(endpoints.PostEndpoint)
	return endpoints, nil
}

func createClientTLSTransport() (*http.Client, error) {

	cert, err := tls.LoadX509KeyPair("/tls/client.crt", "/tls/client.key")
	if err != nil {
		return nil, err
	}

	caCert, err := ioutil.ReadFile("/tls/ca/cacert.pem")
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	return client, nil
}
