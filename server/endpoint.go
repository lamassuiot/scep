package scepserver

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/sd"
	consulsd "github.com/go-kit/kit/sd/consul"
	"github.com/go-kit/kit/sd/lb"
	"github.com/go-kit/kit/tracing/opentracing"
	httptransport "github.com/go-kit/kit/transport/http"
	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
)

// possible SCEP operations
const (
	getCACaps     = "GetCACaps"
	getCACert     = "GetCACert"
	pkiOperation  = "PKIOperation"
	getNextCACert = "GetNextCACert"
)

type Endpoints struct {
	HealthEndpoint endpoint.Endpoint
	GetEndpoint    endpoint.Endpoint
	PostEndpoint   endpoint.Endpoint

	mtx          sync.RWMutex
	capabilities []byte
}

func (e *Endpoints) GetCACaps(ctx context.Context) ([]byte, error) {
	request := SCEPRequest{Operation: getCACaps}
	response, err := e.GetEndpoint(ctx, request)
	if err != nil {
		return nil, err
	}
	resp := response.(SCEPResponse)

	e.mtx.Lock()
	e.capabilities = resp.Data
	e.mtx.Unlock()

	return resp.Data, resp.Err
}

func (e *Endpoints) Supports(cap string) bool {
	e.mtx.RLock()
	defer e.mtx.RUnlock()

	if len(e.capabilities) == 0 {
		e.mtx.RUnlock()
		e.GetCACaps(context.Background())
		e.mtx.RLock()
	}
	return bytes.Contains(e.capabilities, []byte(cap))
}

func (e *Endpoints) GetCACert(ctx context.Context) ([]byte, int, error) {
	request := SCEPRequest{Operation: getCACert}
	response, err := e.GetEndpoint(ctx, request)
	if err != nil {
		return nil, 0, err
	}
	resp := response.(SCEPResponse)
	return resp.Data, resp.CACertNum, resp.Err
}

func (e *Endpoints) PKIOperation(ctx context.Context, msg []byte) ([]byte, error) {
	var ee endpoint.Endpoint
	if e.Supports("POSTPKIOperation") || e.Supports("SCEPStandard") {
		ee = e.PostEndpoint
	} else {
		ee = e.GetEndpoint
	}

	request := SCEPRequest{Operation: pkiOperation, Message: msg}
	response, err := ee(ctx, request)
	if err != nil {
		return nil, err
	}
	resp := response.(SCEPResponse)
	return resp.Data, resp.Err
}

func (e *Endpoints) GetNextCACert(ctx context.Context) ([]byte, error) {
	var request SCEPRequest
	response, err := e.GetEndpoint(ctx, request)
	if err != nil {
		return nil, err
	}
	resp := response.(SCEPResponse)
	return resp.Data, resp.Err
}

func (e *Endpoints) Health(ctx context.Context) bool {
	var request HealthRequest
	response, err := e.HealthEndpoint(ctx, request)
	if err != nil {
		return false
	}
	resp := response.(HealthResponse)
	return resp.Healthy
}

func MakeServerEndpoints(svc Service, otTracer stdopentracing.Tracer) *Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(svc)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}
	var getEndpoint endpoint.Endpoint
	{
		getEndpoint = MakeSCEPEndpoint(svc)
		getEndpoint = opentracing.TraceServer(otTracer, "GetSCEPOperation")(getEndpoint)
	}
	var postEndpoint endpoint.Endpoint
	{
		postEndpoint = MakeSCEPEndpoint(svc)
		postEndpoint = opentracing.TraceServer(otTracer, "PostSCEPOperation")(postEndpoint)
	}

	return &Endpoints{
		HealthEndpoint: healthEndpoint,
		GetEndpoint:    getEndpoint,
		PostEndpoint:   postEndpoint,
	}
}

// MakeClientEndpoints returns an Endpoints struct where each endpoint invokes
// the corresponding method on the remote instance, via a transport/http.Client.
// Useful in a SCEP client.
func MakeClientEndpoints(instance string, httpc *http.Client) (*Endpoints, error) {
	if !strings.HasPrefix(instance, "http") {
		instance = "http://" + instance
	}
	tgt, err := url.Parse(instance)
	if err != nil {
		return nil, err
	}

	options := []httptransport.ClientOption{
		httptransport.SetClient(httpc),
	}

	return &Endpoints{
		HealthEndpoint: httptransport.NewClient(
			"GET",
			tgt,
			EncodeHealthRequest,
			DecodeHealthResponse,
			options...).Endpoint(),
		GetEndpoint: httptransport.NewClient(
			"GET",
			tgt,
			EncodeSCEPRequest,
			DecodeSCEPResponse,
			options...).Endpoint(),
		PostEndpoint: httptransport.NewClient(
			"POST",
			tgt,
			EncodeSCEPRequest,
			DecodeSCEPResponse,
			options...).Endpoint(),
	}, nil
}

func MakeConsulClientEndpoints(instance string, duration time.Duration, instancer *consulsd.Instancer, logger log.Logger, otTracer stdopentracing.Tracer) (*Endpoints, error) {
	var healthEndpoint, getEndpoint, postEndpoint endpoint.Endpoint
	ctx := context.Background()

	healthFactory := makeHealthFactory(ctx, "GET", instance, logger, otTracer)
	healthEndpointer := sd.NewEndpointer(instancer, healthFactory, logger)
	healthBalancer := lb.NewRoundRobin(healthEndpointer)
	healthEntry := lb.Retry(1, duration, healthBalancer)
	healthEndpoint = healthEntry
	healthEndpoint = opentracing.TraceClient(otTracer, "Health")(healthEndpoint)

	getFactory := makeSCEPFactory(ctx, "GET", instance, logger, otTracer)
	getEndpointer := sd.NewEndpointer(instancer, getFactory, logger)
	getBalancer := lb.NewRoundRobin(getEndpointer)
	getEntry := lb.Retry(1, duration, getBalancer)
	getEndpoint = getEntry
	getEndpoint = opentracing.TraceClient(otTracer, "GetSCEPOperation")(getEndpoint)

	postFactory := makeSCEPFactory(ctx, "POST", instance, logger, otTracer)
	postEndpointer := sd.NewEndpointer(instancer, postFactory, logger)
	postBalancer := lb.NewRoundRobin(postEndpointer)
	postEntry := lb.Retry(1, duration, postBalancer)
	postEndpoint = postEntry
	postEndpoint = opentracing.TraceClient(otTracer, "PostSCEPOperation")(postEndpoint)

	return &Endpoints{
		HealthEndpoint: healthEndpoint,
		GetEndpoint:    getEndpoint,
		PostEndpoint:   postEndpoint,
	}, nil

}

func makeHealthFactory(_ context.Context, method, path string, logger log.Logger, otTracer stdopentracing.Tracer) sd.Factory {
	return func(instance string) (endpoint.Endpoint, io.Closer, error) {
		if !strings.HasPrefix(instance, "http") {
			instance = "http://" + instance
		}

		tgt, err := url.Parse(instance)
		if err != nil {
			return nil, nil, err
		}

		options := []httptransport.ClientOption{}

		return httptransport.NewClient(
			method,
			tgt,
			EncodeHealthRequest,
			DecodeHealthResponse,
			append(options, httptransport.ClientBefore(opentracing.ContextToHTTP(otTracer, logger)))...,
		).Endpoint(), nil, nil

	}
}

func makeSCEPFactory(_ context.Context, method, path string, logger log.Logger, otTracer stdopentracing.Tracer) sd.Factory {
	return func(instance string) (endpoint.Endpoint, io.Closer, error) {
		if !strings.HasPrefix(instance, "http") {
			instance = "http://" + instance + "/scep"
		}

		tgt, err := url.Parse(instance)
		if err != nil {
			return nil, nil, err
		}

		options := []httptransport.ClientOption{}

		return httptransport.NewClient(
			method,
			tgt,
			EncodeSCEPRequest,
			DecodeSCEPResponse,
			append(options, httptransport.ClientBefore(opentracing.ContextToHTTP(otTracer, logger)))...,
		).Endpoint(), nil, nil

	}
}

func MakeSCEPEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(SCEPRequest)
		resp := SCEPResponse{operation: req.Operation}
		switch req.Operation {
		case "GetCACaps":
			resp.Data, resp.Err = svc.GetCACaps(ctx)
		case "GetCACert":
			resp.Data, resp.CACertNum, resp.Err = svc.GetCACert(ctx)
		case "PKIOperation":
			resp.Data, resp.Err = svc.PKIOperation(ctx, req.Message)
		default:
			return nil, errors.New("operation not implemented")
		}
		return resp, nil
	}
}

func MakeHealthEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := svc.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}

type HealthRequest struct{}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}

// SCEPRequest is a SCEP server request.
type SCEPRequest struct {
	Operation string
	Message   []byte
}

func (r SCEPRequest) scepOperation() string { return r.Operation }

// SCEPResponse is a SCEP server response.
// Business errors will be encoded as a CertRep message
// with pkiStatus FAILURE and a failInfo attribute.
type SCEPResponse struct {
	operation string
	CACertNum int
	Data      []byte
	Err       error
}

func (r SCEPResponse) scepOperation() string { return r.operation }

// EndpointLoggingMiddleware returns an endpoint middleware that logs the
// duration of each invocation, and the resulting error, if any.
func EndpointLoggingMiddleware(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			var keyvals []interface{}
			// check if this is a scep endpoint, if it is, append the method to the log.
			if oper, ok := request.(interface {
				scepOperation() string
			}); ok {
				keyvals = append(keyvals, "op", oper.scepOperation())
			}
			defer func(begin time.Time) {
				logger.Log(append(keyvals, "error", err, "took", time.Since(begin))...)
			}(time.Now())
			return next(ctx, request)

		}
	}
}
