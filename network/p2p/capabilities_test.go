package p2p

import (
	"context"
	"testing"

	golog "github.com/ipfs/go-log"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
)

func TestCapabilitiesDiscovery(t *testing.T) {
	golog.SetDebugLogging()
	var caps []*CapabilitiesDiscovery
	var addrs []peer.AddrInfo
	testSize := 3
	for i := 0; i < testSize; i++ {
		tempdir := t.TempDir()
		capD, err := MakeCapabilitiesDiscovery(context.Background(), config.GetDefaultLocal(), tempdir, "devtestnet", logging.Base(), []*peer.AddrInfo{})
		require.NoError(t, err)
		caps = append(caps, capD)
		addrs = append(addrs, peer.AddrInfo{
			ID:    capD.Host().ID(),
			Addrs: capD.Host().Addrs(),
		})
	}
	for _, capD := range caps {
		peersAdded := 0
		for _, addr := range addrs {
			added, err := capD.AddPeer(addr)
			require.NoError(t, err)
			require.True(t, added)
			peersAdded++
		}
		err := capD.dht.Bootstrap(context.Background())
		require.NoError(t, err)
		capD.dht.ForceRefresh()
		require.Equal(t, peersAdded, capD.dht.RoutingTable().Size())
	}
}
