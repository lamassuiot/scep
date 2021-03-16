package configs

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Port string

	ConsulProtocol string
	ConsulHost     string
	ConsulPort     string
	ConsulCA       string

	ProxyHost string
	ProxyPort string
	ProxyCA   string

	CertFile    string
	KeyFile     string
	AuthKeyFile string
	ServerPort  string
	SCEPMapping map[string]string
}

func NewConfig(prefix string) (Config, error) {
	var cfg Config
	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}
