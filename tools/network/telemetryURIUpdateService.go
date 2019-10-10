package network

import (
	"fmt"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

func StartTelemetryURIUpdateService(interval time.Duration, cfg config.Local, genesisNetwork protocol.NetworkID, log logging.Logger, abort chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		updateTelemetryURI := func() {
			uri := lookupTelemetryURI(cfg, genesisNetwork, log)

			if uri != "" && uri != log.GetTelemetryURI() {
				log.UpdateTelemetryURI(uri)
			}
		}

		// Update the telemetry URI immediatly, followed by once every <interval>
		updateTelemetryURI()
		for {
			select {
				case <-ticker.C:
					updateTelemetryURI()
				case <-abort:
					return
			}
		}
	}()
}

func lookupTelemetryURI(cfg config.Local, genesisNetwork protocol.NetworkID, log logging.Logger) string {
	bootstrapArray := cfg.DNSBootstrapArray(genesisNetwork)
	for _, bootstrapID := range bootstrapArray {
		telemetrySRV := fmt.Sprintf("telemetry.%s", bootstrapID)
		addrs, err := ReadFromBootstrap(telemetrySRV, cfg.FallbackDNSResolverAddress)
		if err != nil {
			log.Warn("An issue occurred reading telemetry entry for: %s", telemetrySRV)
		} else if len(addrs) == 0 {
			log.Warn("No telemetry entry for: %s", telemetrySRV)
		} else if addrs[0] != log.GetTelemetryURI() {
			return addrs[0]
		}
	}
	return ""
}
