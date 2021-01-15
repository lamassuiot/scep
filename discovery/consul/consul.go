package consul

import (
	"strconv"

	"github.com/micromdm/scep/discovery"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	consulsd "github.com/go-kit/kit/sd/consul"
	"github.com/hashicorp/consul/api"
)

type ServiceDiscovery struct {
	client    consulsd.Client
	proxyHost string
	proxyPort string
	logger    log.Logger
	registrar *consulsd.Registrar
}

func NewServiceDiscovery(consulProtocol string, consulHost string, consulPort string, proxyHost string, proxyPort string, logger log.Logger) (discovery.Service, error) {
	consulConfig := api.DefaultConfig()
	consulConfig.Address = consulProtocol + "://" + consulHost + ":" + consulPort
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		level.Error(logger).Log("err", err, "Could not start Consul API Client")
		return nil, err
	}
	client := consulsd.NewClient(consulClient)
	return &ServiceDiscovery{client: client, proxyHost: proxyHost, proxyPort: proxyPort, logger: logger}, nil
}

func (sd *ServiceDiscovery) Register(advProtocol string, advHost string, advPort string) error {
	check := api.AgentServiceCheck{
		HTTP:          advProtocol + "://" + advHost + ":" + advPort + "/health",
		Interval:      "10s",
		Timeout:       "1s",
		TLSSkipVerify: true,
		Notes:         "Basic health checks",
	}
	port, _ := strconv.Atoi(advPort)
	asr := api.AgentServiceRegistration{
		ID:      advHost,
		Name:    advHost,
		Address: advHost,
		Port:    port,
		Tags:    []string{"scep", advHost},
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
