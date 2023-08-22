package p2p

import (
	"context"
	"io"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	libpeerstore "github.com/libp2p/go-libp2p/core/peerstore"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	algoDht "github.com/algorand/go-algorand/network/p2p/dht"
	"github.com/algorand/go-algorand/network/p2p/peerstore"
)

type capability string

const (
	archival    capability = "archival"
	catchpoints            = "catchpointStoring"
)

const operationTimeout = time.Second * 5
const advertisementInterval = time.Hour * 22

type CapabilitiesDiscovery struct {
	io.Closer
	disc discovery.Discovery
	dht  *dht.IpfsDHT
	log  logging.Logger
}

func (c *CapabilitiesDiscovery) Advertise(ctx context.Context, ns string, opts ...discovery.Option) (time.Duration, error) {
	return c.disc.Advertise(ctx, ns, opts...)
}

func (c *CapabilitiesDiscovery) FindPeers(ctx context.Context, ns string, opts ...discovery.Option) (<-chan peer.AddrInfo, error) {
	return c.disc.FindPeers(ctx, ns, opts...)
}

func (c *CapabilitiesDiscovery) Close() error {
	return c.dht.Close()
}

func (c *CapabilitiesDiscovery) Host() host.Host {
	return c.dht.Host()
}

func (c *CapabilitiesDiscovery) AddPeer(p peer.AddrInfo) (bool, error) {
	c.Host().Peerstore().AddAddrs(p.ID, p.Addrs, libpeerstore.TempAddrTTL)
	return c.dht.RoutingTable().TryAddPeer(p.ID, true, true)
}

func (c *CapabilitiesDiscovery) AdvertiseCapabilities(capabilities ...capability) {
	go func() {
		ticker := time.NewTicker(advertisementInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.dht.Context().Done():
				return
			case <-ticker.C:
				var err error
				for _, capa := range capabilities {
					_, err0 := c.Advertise(c.dht.Context(), string(capa))
					if err0 != nil {
						err = err0
						c.log.Errorf("failed to advertise for capability %s: %v", capa, err)
						break
					}
					c.log.Infof("advertised capability %s", capa)
				}
				// If we failed to advertise, retry every 10 seconds until successful
				if err != nil {
					ticker.Reset(time.Second * 10)
				} else {
					// Otherwise, ensure we're at the correct interval
					ticker.Reset(advertisementInterval)
				}
			}
		}
	}()

}

func MakeCapabilitiesDiscovery(ctx context.Context, cfg config.Local, datadir string, network string, log logging.Logger, bootstrapPeers []*peer.AddrInfo) (*CapabilitiesDiscovery, error) {
	pstore, err := peerstore.NewPeerStore(bootstrapPeers)
	if err != nil {
		return nil, err
	}
	h, err := makeHost(cfg, datadir, pstore)
	discDht, err := algoDht.MakeDHT(ctx, h, network, bootstrapPeers)
	if err != nil {
		return nil, err
	}
	discImpl, err := algoDht.MakeDiscovery(discDht)
	if err != nil {
		return nil, err
	}
	return &CapabilitiesDiscovery{
		disc: discImpl,
		dht:  discDht,
		log:  log,
	}, nil
}
