package main

import "fmt"

func main() {
	cfg, err := LoadCfg("config.yaml")
	if err != nil {
		panic(fmt.Errorf("error loading config: %w", err))
	}

	if err := Listen(&cfg); err != nil {
		fmt.Println(err)
	}
}
