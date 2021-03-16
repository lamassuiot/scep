package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/micromdm/scep/extension/api"
	"github.com/micromdm/scep/extension/client/scep"
	"github.com/micromdm/scep/extension/configs"
	"github.com/micromdm/scep/extension/discovery/consul"
	"github.com/micromdm/scep/extension/utils"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	jaegercfg "github.com/uber/jaeger-client-go/config"
)

func main() {
	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
		logger = level.NewFilter(logger, level.AllowInfo())
	}

	cfg, err := configs.NewConfig("scepextension")
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read environment configuration values")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Environment configuration values loaded")

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

	client := scep.NewClient(cfg.CertFile, cfg.KeyFile, cfg.ServerPort, cfg.ConsulProtocol, cfg.ConsulHost, cfg.ConsulPort, cfg.ConsulCA, cfg.SCEPMapping, logger, tracer)
	level.Info(logger).Log("msg", "Remote SCEP Client started")

	fieldKeys := []string{"method", "error"}
	var s api.Service
	{
		s = api.NewDeviceService(client)
		s = api.LoggingMidleware(logger)(s)
		s = api.NewInstumentingMiddleware(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "device_manufacturing_system",
				Subsystem: "manufacturing_service",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "device_manufacturing_system",
				Subsystem: "manufacturing_service",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
		)(s)
	}

	consulsd, err := consul.NewServiceDiscovery(cfg.ProxyHost, cfg.ProxyPort, cfg.ConsulProtocol, cfg.ConsulHost, cfg.ConsulPort, cfg.ConsulCA, logger)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with Consul Service Discovery")
		os.Exit(1)
	}
	err = consulsd.Register("https", "scepextension", cfg.Port)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not register service liveness information to Consul")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Service liveness information registered to Consul")

	proxyCAPool, err := utils.CreateCAPool(cfg.ProxyCA)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not create Proxy CA pool")
	}
	level.Info(logger).Log("msg", "Proxy CA pool created")

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: nil,
		TLSConfig: &tls.Config{
			RootCAs: proxyCAPool,
		},
	}
	level.Info(logger).Log("msg", "Server created and configured")

	mux := http.NewServeMux()

	mux.Handle("/v1/", api.MakeHTTPHandler(s, log.With(logger, "component", "HTTP"), tracer))
	http.Handle("/", accessControl(mux))
	http.Handle("/metrics", promhttp.Handler())

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	go func() {
		level.Info(logger).Log("transport", "HTTPS", "address", ":"+cfg.Port, "msg", "listening")
		errs <- server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	}()

	level.Info(logger).Log("exit", <-errs)
	err = consulsd.Deregister()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not deregister service liveness information from Consul")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Service liveness information deregistered from Consul")
}
func accessControl(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		h.ServeHTTP(w, r)
	})
}
