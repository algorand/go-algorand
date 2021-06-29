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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
   "github.com/algorand/go-algorand/testPartitioning"
)

type telemetryURIUpdaterTest struct {
	telemetryURIUpdater
	readFromSRVResults map[string][]string
}

func (t *telemetryURIUpdaterTest) readFromSRV(protocol string, bootstrapID string) (addrs []string, err error) {
	if addr, ok := t.readFromSRVResults[protocol+bootstrapID]; ok {
		return addr, nil
	}
	fmt.Printf("no result for %s %s\n", protocol, bootstrapID)
	return nil, fmt.Errorf("no cached results")
}

func makeTelemetryURIUpdaterTest(genesisNetwork protocol.NetworkID) *telemetryURIUpdaterTest {
	t := &telemetryURIUpdaterTest{
		telemetryURIUpdater: telemetryURIUpdater{
			cfg:            config.GetDefaultLocal(),
			log:            logging.Base(),
			genesisNetwork: genesisNetwork,
		},
		readFromSRVResults: make(map[string][]string),
	}
	t.srvReader = t
	return t
}

func (t *telemetryURIUpdaterTest) add(protocol, bootstrap string, addrs []string) {
	t.readFromSRVResults[protocol+bootstrap] = addrs
}

func TestTelemetryURILookup(t *testing.T) {
   testPartitioning.PartitionTest(t)


	// trivial success case.
	uriUpdater := makeTelemetryURIUpdaterTest(config.Devnet)
	uriUpdater.add("tcp", "devnet.algodev.network", []string{"myhost:4160"})
	uri := uriUpdater.lookupTelemetryURL()
	require.NotNil(t, uri)
	require.Equal(t, "http://myhost:4160", uri.String())

	// check https prefixing
	uriUpdater = makeTelemetryURIUpdaterTest(config.Devnet)
	uriUpdater.add("tcp", "devnet.algodev.network", []string{"https://myhost:4160"})
	uri = uriUpdater.lookupTelemetryURL()
	require.NotNil(t, uri)
	require.Equal(t, "https://myhost:4160", uri.String())

	// check https priority
	uriUpdater = makeTelemetryURIUpdaterTest(config.Devnet)
	uriUpdater.add("tcp", "devnet.algodev.network", []string{"myhost2:4160"})
	uriUpdater.add("tls", "devnet.algodev.network", []string{"myhost1:4160"})
	uri = uriUpdater.lookupTelemetryURL()
	require.NotNil(t, uri)
	require.Equal(t, "https://myhost1:4160", uri.String())

	// check fallback
	uriUpdater = makeTelemetryURIUpdaterTest(config.Devnet)
	uriUpdater.add("tcp", "default.algodev.network", []string{"fallbackhost:8123"})
	uri = uriUpdater.lookupTelemetryURL()
	require.NotNil(t, uri)
	require.Equal(t, "http://fallbackhost:8123", uri.String())
}
