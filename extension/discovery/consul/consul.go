package consul

import (
	"math/rand"
	"strconv"

	"github.com/micromdm/scep/discovery"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	consulsd "github.com/go-kit/kit/sd/consul"
	"github.com/hashicorp/consul/api"
)

type ServiceDiscovery struct {
	client    consulsd.Client
	logger    log.Logger
	registrar *consulsd.Registrar
	proxyHost string
	proxyPort string
}

func NewServiceDiscovery(proxyHost string, proxyPort string, consulProtocol string, consulHost string, consulPort string, CA string, logger log.Logger) (discovery.Service, error) {
	consulConfig := api.DefaultConfig()
	consulConfig.Address = consulProtocol + "://" + consulHost + ":" + consulPort
	tlsConf := &api.TLSConfig{CAFile: CA}
	consulConfig.TLSConfig = *tlsConf
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		level.Error(logger).Log("err", err, "Could not start Consul API Client")
		return nil, err
	}
	client := consulsd.NewClient(consulClient)
	return &ServiceDiscovery{client: client, logger: logger, proxyHost: proxyHost, proxyPort: proxyPort}, nil
}

func (sd *ServiceDiscovery) Register(advProtocol string, advHost string, advPort string) error {
	check := api.AgentServiceCheck{
		HTTP:          advProtocol + "://" + advHost + ":" + advPort + "/v1/health",
		Interval:      "10s",
		Timeout:       "1s",
		TLSSkipVerify: true,
		Notes:         "Basic health checks",
	}
	port, _ := strconv.Atoi(sd.proxyPort)
	num := rand.Intn(100)
	asr := api.AgentServiceRegistration{
		ID:      "scepextension" + strconv.Itoa(num),
		Name:    "scepextension",
		Address: sd.proxyHost,
		Port:    port,
		Tags:    []string{"scep", "extension"},
		Check:   &check,
	}
	sd.registrar = consulsd.NewRegistrar(sd.client, &asr, sd.logger)
	sd.registrar.Register()
	return nil
}

func (sd *ServiceDiscovery) Deregister() error {
	sd.registrar.Deregister()
	return nil
}
