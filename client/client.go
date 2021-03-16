package scepclient

import (
	"net/http"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	consulsd "github.com/go-kit/kit/sd/consul"
	scepserver "github.com/micromdm/scep/server"
	stdopentracing "github.com/opentracing/opentracing-go"
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

func NewSD(serverURL string, duration time.Duration, instancer *consulsd.Instancer, logger log.Logger, otTracer stdopentracing.Tracer) (Client, error) {
	endpoints, err := scepserver.MakeConsulClientEndpoints(serverURL, duration, instancer, logger, otTracer)
	if err != nil {
		return nil, err
	}
	logger = level.Info(logger)
	endpoints.GetEndpoint = scepserver.EndpointLoggingMiddleware(logger)(endpoints.GetEndpoint)
	endpoints.PostEndpoint = scepserver.EndpointLoggingMiddleware(logger)(endpoints.PostEndpoint)
	return endpoints, nil
}
