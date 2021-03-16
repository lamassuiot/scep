package extensionclient

import (
	"net/http"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	consulsd "github.com/go-kit/kit/sd/consul"
	extensionserver "github.com/micromdm/scep/extension/api"
	stdopentracing "github.com/opentracing/opentracing-go"
)

// Client is a SCEP Extension Client
type Client interface {
	extensionserver.Service
}

func NewSD(serverURL string, duration time.Duration, instancer *consulsd.Instancer, logger log.Logger, httpc *http.Client, otTracer stdopentracing.Tracer) (Client, error) {
	endpoints, err := extensionserver.MakeConsulClientEndpoints(serverURL, duration, instancer, httpc, logger, otTracer)
	if err != nil {
		return nil, err
	}
	logger = level.Info(logger)
	return endpoints, nil
}
