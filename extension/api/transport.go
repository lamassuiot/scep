package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/go-kit/kit/auth/jwt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"

	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	stdopentracing "github.com/opentracing/opentracing-go"
)

func MakeHTTPHandler(s Service, logger log.Logger, otTracer stdopentracing.Tracer) http.Handler {
	r := mux.NewRouter()
	e := MakeServerEndpoints(s, otTracer)

	options := []httptransport.ServerOption{
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(encodeError),
		httptransport.ServerBefore(jwt.HTTPToContext()),
	}

	r.Methods("GET").Path("/v1/health").Handler(httptransport.NewServer(
		e.HealthEndpoint,
		decodeHealthRequest,
		encodeResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "Health", logger)))...,
	))

	r.Methods("POST").Path("/v1/device/config").Handler(httptransport.NewServer(
		e.PostSetConfigEndpoint,
		decodePostSetConfigRequest,
		encodeResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "PostSetConfig", logger)))...,
	))

	r.Methods("POST").Path("/v1/device").Handler(httptransport.NewServer(
		e.PostGetCRTEndpoint,
		decodePostGetCRTRequest,
		encodePostGetCRTResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "PostGetCRT", logger)))...,
	))

	return r
}

type errorer interface {
	error() error
}

const maxPayloadSize = 2 << 20

func encodeHealthRequest(ctx context.Context, r *http.Request, request interface{}) error {
	r.URL.Path = "/v1/health"
	return nil
}

func decodeHealthRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req healthRequest
	return req, nil
}

func decodeHealthResponse(ctx context.Context, r *http.Response) (interface{}, error) {
	var response healthResponse
	if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

func encodePostSetConfigRequest(ctx context.Context, r *http.Request, request interface{}) error {
	r.URL.Path = "/v1/device/config"
	return encodeRequest(ctx, r, request)

}

func decodePostSetConfigRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var reqData postSetConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		return nil, err
	}
	return reqData, nil
}

func decodePostSetConfigResponse(ctx context.Context, r *http.Response) (interface{}, error) {
	var response postSetConfigResponse
	if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

func encodePostGetCRTRequest(ctx context.Context, r *http.Request, request interface{}) error {
	r.URL.Path = "/v1/device"
	return encodeRequest(ctx, r, request)
}

func decodePostGetCRTRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var reqData postGetCRTRequest
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		return nil, err
	}
	return reqData, nil
}

func encodePostGetCRTResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.(postGetCRTResponse)
	if resp.Err != nil {
		encodeError(ctx, resp.Err, w)
		return nil
	}
	w.Header().Set("Content-Type", "application/pkcs10; charset=utf-8")
	w.Write(resp.Data)
	return nil
}
func decodePostGetCRTResponse(ctx context.Context, r *http.Response) (interface{}, error) {
	data, err := ioutil.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
	if err != nil {
		return nil, err
	}
	if r.StatusCode != 200 {
		return postGetCRTResponse{Data: nil, Err: errors.New(string(data))}, nil
	}
	return postGetCRTResponse{Data: data, Err: nil}, nil
}

func encodeRequest(_ context.Context, req *http.Request, request interface{}) error {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(request)
	if err != nil {
		return err
	}
	req.Body = ioutil.NopCloser(&buf)
	return nil
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.
		encodeError(ctx, e.error(), w)

		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	http.Error(w, err.Error(), codeFrom(err))
}

func codeFrom(err error) int {
	switch err {
	case errUnableParseCSR:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
