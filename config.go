package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Cfg struct {
	Port              string   `yaml:"port"`
	Interface         string   `yaml:"interface"`
	AuthorizedKeyFile string   `yaml:"authorized_key_file"`
	PrivateKeyFile    string   `yaml:"private_key_file"`
	AuthorizedUsers   []string `yaml:"authorized_users"`
}

func LoadCfg(file string) (Cfg, error) {
	var config Cfg
	f, err := os.Open(file)
	if err != nil {
		return Cfg{}, fmt.Errorf("could not read config file: %w", err)
	}

	decoder := yaml.NewDecoder(f)
	if err := decoder.Decode(&config); err != nil {
		return Cfg{}, fmt.Errorf("could not parse config: %w", err)
	}

	return config, nil
}
