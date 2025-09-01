package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	port         = "8000"
	netInterface = "0.0.0.0"
	passwdFile   = "/etc/passwd"
)

type Cfg struct {
	Port              string   `yaml:"port"`
	Interface         string   `yaml:"interface"`
	AuthorizedKeyFile string   `yaml:"authorized_key_file"`
	PrivateKeyFile    string   `yaml:"private_key_file"`
	AuthorizedUsers   []string `yaml:"authorized_users"`
	PasswdFile        string   `yaml:"passwd_file"`
}

func LoadCfg(file string) (Cfg, error) {
	config := Cfg{
		Port:       port,
		Interface:  netInterface,
		PasswdFile: passwdFile,
	}
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
