// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package network

import (
	"net/url"
	"strings"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type telemetrySrvReader interface {
	readFromSRV(protocol string, bootstrapID string) (addrs []string, err error)
}

type telemetryURIUpdater struct {
	interval       time.Duration
	cfg            config.Local
	genesisNetwork protocol.NetworkID
	log            logging.Logger
	abort          chan struct{}
	srvReader      telemetrySrvReader
}

// StartTelemetryURIUpdateService starts a go routine which queries SRV records for a telemetry URI every <interval>
func StartTelemetryURIUpdateService(interval time.Duration, cfg config.Local, genesisNetwork protocol.NetworkID, log logging.Logger, abort chan struct{}) {
	updater := &telemetryURIUpdater{
		interval:       interval,
		cfg:            cfg,
		genesisNetwork: genesisNetwork,
		log:            log,
		abort:          abort,
	}
	updater.srvReader = updater
	updater.Start()

}
func (t *telemetryURIUpdater) Start() {
	go func() {
		ticker := time.NewTicker(t.interval)
		defer ticker.Stop()

		updateTelemetryURI := func() {
			endpointURL := t.lookupTelemetryURL()

			if endpointURL != nil && endpointURL.String() != t.log.GetTelemetryURI() {
				err := t.log.UpdateTelemetryURI(endpointURL.String())
				if err != nil {
					t.log.Warnf("Unable to update telemetry URI to '%s' : %v", endpointURL.String(), err)
				}
			}
		}

		// Update telemetry right away, followed by once every <interval>
		updateTelemetryURI()
		for {
			select {
			case <-ticker.C:
				updateTelemetryURI()
			case <-t.abort:
				return
			}
		}
	}()
}

func (t *telemetryURIUpdater) lookupTelemetryURL() (url *url.URL) {
	bootstrapArray := t.cfg.DNSBootstrapArray(t.genesisNetwork)
	bootstrapArray = append(bootstrapArray, "default.algodev.network")
	for _, bootstrapID := range bootstrapArray {
		addrs, err := t.srvReader.readFromSRV("tls", bootstrapID)
		if err != nil {
			t.log.Infof("An issue occurred reading telemetry entry for '_telemetry._tls.%s': %v", bootstrapID, err)
		} else if len(addrs) == 0 {
			t.log.Infof("No telemetry entry for: '_telemetry._tls.%s'", bootstrapID)
		} else {
			for _, addr := range addrs {
				// the addr that we received from ReadFromSRV contains host:port, we need to prefix that with the schema. since it's the tls, we want to use https.
				url, err = url.Parse("https://" + addr)
				if err != nil {
					t.log.Infof("a telemetry endpoint '%s' was retrieved for '_telemerty._tls.%s'. This does not seems to be a valid endpoint and will be ignored(%v).", addr, bootstrapID, err)
					continue
				}
				return url
			}
		}

		addrs, err = t.srvReader.readFromSRV("tcp", bootstrapID)
		if err != nil {
			t.log.Infof("An issue occurred reading telemetry entry for '_telemetry._tcp.%s': %v", bootstrapID, err)
		} else if len(addrs) == 0 {
			t.log.Infof("No telemetry entry for: '_telemetry._tcp.%s'", bootstrapID)
		} else {
			for _, addr := range addrs {
				if strings.HasPrefix(addr, "https://") {
					// the addr that we received from ReadFromSRV should contain host:port. however, in some cases, it might contain a https prefix, where we want to take it as is.
					url, err = url.Parse(addr)
				} else {
					// the addr that we received from ReadFromSRV contains host:port, we need to prefix that with the schema. since it's the tcp, we want to use http.
					url, err = url.Parse("http://" + addr)
				}

				if err != nil {
					t.log.Infof("a telemetry endpoint '%s' was retrieved for '_telemerty._tcp.%s'. This does not seems to be a valid endpoint and will be ignored(%v).", addr, bootstrapID, err)
					continue
				}
				return url
			}
		}
	}

	t.log.Warn("No telemetry endpoint was found.")
	return nil
}

func (t *telemetryURIUpdater) readFromSRV(protocol string, bootstrapID string) (addrs []string, err error) {
	return ReadFromSRV("telemetry", protocol, bootstrapID, t.cfg.FallbackDNSResolverAddress, t.cfg.DNSSecuritySRVEnforced())
}
