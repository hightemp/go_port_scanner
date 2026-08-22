package main

import (
	appconfig "github.com/hightemp/go_port_scanner/internal/config"
	"github.com/hightemp/go_port_scanner/internal/probe"
)

func newProbeRegistry(configuration appconfig.Config) (*probe.Registry, error) {
	configured := configuration.EnabledProbeDefinitions()
	if len(configured) == 0 {
		return nil, nil
	}

	definitions := make([]probe.Definition, 0, len(configured))
	for _, definition := range configured {
		definitions = append(definitions, probe.Definition{
			Name:  definition.Name,
			Ports: definition.Ports,
		})
	}
	return probe.NewRegistry(probe.Config{
		Timeout:               configuration.Probes.Timeout.Duration,
		TLSInsecureSkipVerify: configuration.Probes.TLSInsecureSkipVerify,
		Definitions:           definitions,
	})
}
