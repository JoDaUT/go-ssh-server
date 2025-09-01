package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := LoadCfg("config.yaml")
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	sshServer := NewSshServer(&cfg)
	defer sshServer.Close()

	if err := sshServer.Init(); err != nil {
		return err
	}

	if err := sshServer.Listen(); err != nil {
		return err
	}

	if err := sshServer.Accept(); err != nil {
		return err
	}

	return nil
}
