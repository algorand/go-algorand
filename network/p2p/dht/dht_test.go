package dht

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/network/p2p"
	"github.com/algorand/go-algorand/network/p2p/peerstore"
)

func setupDHTHosts(t *testing.T, numHosts int) []*dht.IpfsDHT {
	var hosts []host.Host
	var bootstrapPeers []*peer.AddrInfo
	var dhts []*dht.IpfsDHT
	for i := 0; i < numHosts; i++ {
		tmpdir := t.TempDir()
		pk, err := p2p.GetPrivKey(config.GetDefaultLocal(), tmpdir)
		require.NoError(t, err)
		ps, err := peerstore.NewPeerStore([]*peer.AddrInfo{})
		require.NoError(t, err)
		h, err := libp2p.New(
			libp2p.ListenAddrStrings("/dns4/localhost/tcp/0"),
			libp2p.Identity(pk),
			libp2p.Peerstore(ps))
		require.NoError(t, err)
		hosts = append(hosts, h)
		bootstrapPeers = append(bootstrapPeers, &peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()})
	}
	for _, h := range hosts {
		ht, err := MakeDHT(context.Background(), h, "devtestnet", bootstrapPeers)
		require.NoError(t, err)
		err = ht.Bootstrap(context.Background())
		require.NoError(t, err)
		dhts = append(dhts, ht)
	}
	return dhts
}

func TestDHTBasic(t *testing.T) {
	h, err := libp2p.New()
	require.NoError(t, err)
	dht, err := MakeDHT(context.Background(), h, "devtestnet", []*peer.AddrInfo{})
	require.NoError(t, err)
	_, err = MakeDiscovery(dht)
	require.NoError(t, err)
	err = dht.Bootstrap(context.Background())
	require.NoError(t, err)
}

func TestDHTTwoPeers(t *testing.T) {
	numAdvertisers := 2
	dhts := setupDHTHosts(t, numAdvertisers)
	topic := "foobar"
	for i, ht := range dhts {
		disc, err := MakeDiscovery(ht)
		require.NoError(t, err)
		refreshCtx, _ := context.WithTimeout(context.Background(), time.Second*5)
	peersPopulated:
		for {
			select {
			case <-refreshCtx.Done():
				require.Fail(t, "failed to populate routing table before timeout")
			default:
				if ht.RoutingTable().Size() > 0 {
					break peersPopulated
				}
			}
		}
		_, err = disc.Advertise(context.Background(), topic)
		require.NoError(t, err)

		ctx, _ := context.WithTimeout(context.Background(), time.Second*5)
		var advertisers []peer.AddrInfo
		peersChan, err := disc.FindPeers(ctx, topic, discovery.Limit(numAdvertisers))
	pollingForPeers:
		for {
			select {
			case p, open := <-peersChan:
				if p.ID.Size() > 0 {
					advertisers = append(advertisers, p)
				}
				if !open {
					break pollingForPeers
				}
			}
		}
		// Returned peers will include the querying node's ID since it advertises for the topic as well
		require.Equal(t, i+1, len(advertisers))
	}
}

func TestTopicCid(t *testing.T) {
	/*
		topicMultihash, err := multihash.Sum([]byte(topic), multihash.SHA2_256, -1)
		topicCid := cid.NewCidV1(cid.Raw, topicMultihash)
		require.NoError(t, err)
		dht1Providers, err := dht1.FindProviders(context.TODO(), topicCid)
		require.NoError(t, err)
	*/
}
