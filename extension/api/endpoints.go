package api

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/sd"
	consulsd "github.com/go-kit/kit/sd/consul"
	"github.com/go-kit/kit/sd/lb"
	"github.com/go-kit/kit/tracing/opentracing"
	httptransport "github.com/go-kit/kit/transport/http"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint        endpoint.Endpoint
	PostSetConfigEndpoint endpoint.Endpoint
	PostGetCRTEndpoint    endpoint.Endpoint
}

func (e *Endpoints) Health(ctx context.Context) bool {
	var request healthRequest
	response, err := e.HealthEndpoint(ctx, request)
	if err != nil {
		return false
	}
	resp := response.(healthResponse)
	return resp.Healthy
}

func (e *Endpoints) PostSetConfig(ctx context.Context, CA string) error {
	request := postSetConfigRequest{CA: CA}
	response, err := e.PostSetConfigEndpoint(ctx, request)
	if err != nil {
		return err
	}
	resp := response.(postSetConfigResponse)
	return resp.Err
}

func (e *Endpoints) PostGetCRT(ctx context.Context, csrData []byte) (crtData []byte, err error) {
	request := postGetCRTRequest{CSR: csrData}
	response, err := e.PostGetCRTEndpoint(ctx, request)
	if err != nil {
		return nil, err
	}
	resp := response.(postGetCRTResponse)
	return resp.Data, resp.Err
}

func MakeServerEndpoints(s Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}
	var postSetConfigEndpoint endpoint.Endpoint
	{
		postSetConfigEndpoint = MakePostSetConfigEndpoint(s)
		postSetConfigEndpoint = opentracing.TraceServer(otTracer, "PostSetConfig")(postSetConfigEndpoint)
	}
	var postGetCRTEndpoint endpoint.Endpoint
	{
		postGetCRTEndpoint = MakePostGetCRTEndpoint(s)
		postGetCRTEndpoint = opentracing.TraceServer(otTracer, "PostGetCRT")(postGetCRTEndpoint)
	}
	return Endpoints{
		HealthEndpoint:        healthEndpoint,
		PostSetConfigEndpoint: postSetConfigEndpoint,
		PostGetCRTEndpoint:    postGetCRTEndpoint,
	}
}

func MakeConsulClientEndpoints(instance string, duration time.Duration, instancer *consulsd.Instancer, httpc *http.Client, logger log.Logger, otTracer stdopentracing.Tracer) (*Endpoints, error) {
	var healthEndpoint, postSetConfigEndpoint, postGetCRTEndpoint endpoint.Endpoint

	healthFactory := makeHealthFactory("GET", instance, httpc, logger, otTracer)
	healthEndpointer := sd.NewEndpointer(instancer, healthFactory, logger)
	healthBalancer := lb.NewRoundRobin(healthEndpointer)
	healthEntry := lb.Retry(1, duration, healthBalancer)
	healthEndpoint = healthEntry
	healthEndpoint = opentracing.TraceClient(otTracer, "Health")(healthEndpoint)

	postSetConfigFactory := makePostSetConfigFactory("POST", instance, httpc, logger, otTracer)
	postSetConfigEndpointer := sd.NewEndpointer(instancer, postSetConfigFactory, logger)
	postSetConfigBalancer := lb.NewRoundRobin(postSetConfigEndpointer)
	postSetConfigEntry := lb.Retry(1, duration, postSetConfigBalancer)
	postSetConfigEndpoint = postSetConfigEntry
	postSetConfigEndpoint = opentracing.TraceClient(otTracer, "GetSCEPOperation")(postSetConfigEndpoint)

	postGetCRTFactory := makePostGetCRTFactory("POST", instance, httpc, logger, otTracer)
	postGetCRTEndpointer := sd.NewEndpointer(instancer, postGetCRTFactory, logger)
	postGetCRTBalancer := lb.NewRoundRobin(postGetCRTEndpointer)
	postGetCRTEntry := lb.Retry(1, duration, postGetCRTBalancer)
	postGetCRTEndpoint = postGetCRTEntry
	postGetCRTEndpoint = opentracing.TraceClient(otTracer, "PostSCEPOperation")(postGetCRTEndpoint)

	return &Endpoints{
		HealthEndpoint:        healthEndpoint,
		PostSetConfigEndpoint: postSetConfigEndpoint,
		PostGetCRTEndpoint:    postGetCRTEndpoint,
	}, nil

}

func makeHealthFactory(method, path string, httpc *http.Client, logger log.Logger, otTracer stdopentracing.Tracer) sd.Factory {
	return func(instance string) (endpoint.Endpoint, io.Closer, error) {
		if !strings.HasPrefix(instance, "https") {
			instance = "https://" + instance
		}

		tgt, err := url.Parse(instance)
		if err != nil {
			return nil, nil, err
		}

		options := []httptransport.ClientOption{
			httptransport.SetClient(httpc),
		}

		return httptransport.NewClient(
			method,
			tgt,
			encodeHealthRequest,
			decodeHealthResponse,
			append(options, httptransport.ClientBefore(opentracing.ContextToHTTP(otTracer, logger)))...,
		).Endpoint(), nil, nil

	}
}

func makePostGetCRTFactory(method, path string, httpc *http.Client, logger log.Logger, otTracer stdopentracing.Tracer) sd.Factory {
	return func(instance string) (endpoint.Endpoint, io.Closer, error) {
		if !strings.HasPrefix(instance, "https") {
			instance = "https://" + instance
		}

		tgt, err := url.Parse(instance)
		if err != nil {
			return nil, nil, err
		}

		options := []httptransport.ClientOption{
			httptransport.SetClient(httpc),
		}

		return httptransport.NewClient(
			method,
			tgt,
			encodePostGetCRTRequest,
			decodePostGetCRTResponse,
			append(options, httptransport.ClientBefore(opentracing.ContextToHTTP(otTracer, logger)))...,
		).Endpoint(), nil, nil

	}
}

func makePostSetConfigFactory(method, path string, httpc *http.Client, logger log.Logger, otTracer stdopentracing.Tracer) sd.Factory {
	return func(instance string) (endpoint.Endpoint, io.Closer, error) {
		if !strings.HasPrefix(instance, "http") {
			instance = "https://" + instance
		}

		tgt, err := url.Parse(instance)
		if err != nil {
			return nil, nil, err
		}

		options := []httptransport.ClientOption{
			httptransport.SetClient(httpc),
		}

		return httptransport.NewClient(
			method,
			tgt,
			encodePostSetConfigRequest,
			decodePostSetConfigResponse,
			append(options, httptransport.ClientBefore(opentracing.ContextToHTTP(otTracer, logger)))...,
		).Endpoint(), nil, nil

	}
}

func MakeHealthEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return healthResponse{Healthy: healthy}, nil
	}
}

func MakePostSetConfigEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(postSetConfigRequest)
		err = s.PostSetConfig(ctx, req.CA)
		return postSetConfigResponse{Err: err}, nil
	}
}

func MakePostGetCRTEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(postGetCRTRequest)
		data, err := s.PostGetCRT(ctx, req.CSR)
		return postGetCRTResponse{Data: data, Err: err}, nil
	}
}

type healthRequest struct{}

type healthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}

type postSetConfigRequest struct {
	CA string `json:"ca"`
}

type postSetConfigResponse struct {
	Err error `json:"error,omitempty"`
}

func (r postSetConfigResponse) error() error { return r.Err }

type postGetCRTRequest struct {
	CSR []byte `json:"csr"`
}

type postGetCRTResponse struct {
	Data []byte `json:"crt"`
	Err  error  `json:"error,omitempty"`
}

func (r postGetCRTResponse) error() error { return r.Err }
