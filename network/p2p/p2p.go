// Copyright (C) 2019-2025 Algorand, Inc.
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

package p2p

import (
	"context"
	"encoding/base32"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network/limitcaller"
	pstore "github.com/algorand/go-algorand/network/p2p/peerstore"
	"github.com/algorand/go-algorand/network/phonebook"
	"github.com/algorand/go-algorand/util/metrics"
	"github.com/algorand/go-deadlock"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// SubNextCancellable is an abstraction for pubsub.Subscription
type SubNextCancellable interface {
	Next(ctx context.Context) (*pubsub.Message, error)
	Cancel()
}

// Service defines the interface used by the network integrating with underlying p2p implementation
type Service interface {
	Start() error
	Close() error
	ID() peer.ID // return peer.ID for self
	IDSigner() *PeerIDChallengeSigner
	AddrInfo() peer.AddrInfo // return addrInfo for self

	DialPeersUntilTargetCount(targetConnCount int)
	ClosePeer(peer.ID) error

	Conns() []network.Conn
	ListPeersForTopic(topic string) []peer.ID
	Subscribe(topic string, val pubsub.ValidatorEx) (SubNextCancellable, error)
	Publish(ctx context.Context, topic string, data []byte) error

	// GetHTTPClient returns a rate-limiting libp2p-streaming http client that can be used to make requests to the given peer
	GetHTTPClient(addrInfo *peer.AddrInfo, connTimeStore limitcaller.ConnectionTimeStore, queueingTimeout time.Duration) (*http.Client, error)
}

// serviceImpl manages integration with libp2p and implements the Service interface
type serviceImpl struct {
	log        logging.Logger
	listenAddr string
	host       host.Host
	streams    *streamManager
	pubsub     *pubsub.PubSub
	pubsubCtx  context.Context
	privKey    crypto.PrivKey

	topics   map[string]*pubsub.Topic
	topicsMu deadlock.RWMutex
}

// AlgorandWsProtocol defines a libp2p protocol name for algorand's websockets messages
const AlgorandWsProtocol = "/algorand-ws/1.0.0"

// algorandGUIDProtocolPrefix defines a libp2p protocol name for algorand node telemetry GUID exchange
const algorandGUIDProtocolPrefix = "/algorand-telemetry/1.0.0/"
const algorandGUIDProtocolTemplate = algorandGUIDProtocolPrefix + "%s/%s"

const dialTimeout = 30 * time.Second

// MakeHost creates a libp2p host but does not start listening.
// Use host.Network().Listen() on the returned address to start listening.
func MakeHost(cfg config.Local, datadir string, pstore *pstore.PeerStore) (host.Host, string, error) {
	// load stored peer ID, or make ephemeral peer ID
	privKey, err := GetPrivKey(cfg, datadir)
	if err != nil {
		return nil, "", err
	}

	// muxer supports tweaking fields from yamux.Config
	ymx := *yamux.DefaultTransport
	// user-agent copied from wsNetwork.go
	version := config.GetCurrentVersion()
	ua := fmt.Sprintf("algod/%d.%d (%s; commit=%s; %d) %s(%s)", version.Major, version.Minor, version.Channel, version.CommitHash, version.BuildNumber, runtime.GOOS, runtime.GOARCH)

	var listenAddr string
	var needAddressFilter bool
	if cfg.NetAddress != "" {
		if parsedListenAddr, perr := netAddressToListenAddress(cfg.NetAddress); perr == nil {
			listenAddr = parsedListenAddr

			// check if the listen address is a specific address or a "all interfaces" address (0.0.0.0 or ::)
			// in this case enable the address filter.
			// this also means the address filter is not enabled for NetAddress set to
			// a specific address including loopback and private addresses.
			if manet.IsIPUnspecified(multiaddr.StringCast(listenAddr)) {
				needAddressFilter = true
			}
		} else {
			logging.Base().Warnf("failed to parse NetAddress %s: %v", cfg.NetAddress, perr)
		}
	} else {
		logging.Base().Debug("p2p NetAddress is not set, not listening")
		listenAddr = ""
	}

	var enableMetrics = func(cfg *libp2p.Config) error { cfg.DisableMetrics = false; return nil }
	metrics.DefaultRegistry().Register(&metrics.PrometheusDefaultMetrics)

	var addrFactory func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr
	if needAddressFilter {
		logging.Base().Debug("private addresses filter is enabled")
		addrFactory = addressFilter
	}

	rm, err := configureResourceManager(cfg)
	if err != nil {
		return nil, "", err
	}

	host, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.UserAgent(ua),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Muxer("/yamux/1.0.0", &ymx),
		libp2p.Peerstore(pstore),
		libp2p.NoListenAddrs,
		libp2p.Security(noise.ID, noise.New),
		enableMetrics,
		libp2p.ResourceManager(rm),
		libp2p.AddrsFactory(addrFactory),
	)
	return host, listenAddr, err
}

func configureResourceManager(cfg config.Local) (network.ResourceManager, error) {
	// see https://github.com/libp2p/go-libp2p/tree/master/p2p/host/resource-manager for more details
	scalingLimits := rcmgr.DefaultLimits
	libp2p.SetDefaultServiceLimits(&scalingLimits)
	scaledDefaultLimits := scalingLimits.AutoScale()

	limitConfig := rcmgr.PartialLimitConfig{
		System: rcmgr.ResourceLimits{
			Conns: rcmgr.LimitVal(cfg.IncomingConnectionsLimit),
		},
		// Everything else is default. The exact values will come from `scaledDefaultLimits` above.
	}
	limiter := rcmgr.NewFixedLimiter(limitConfig.Build(scaledDefaultLimits))
	rm, err := rcmgr.NewResourceManager(limiter)
	return rm, err
}

// MakeService creates a P2P service instance
func MakeService(ctx context.Context, log logging.Logger, cfg config.Local, h host.Host, listenAddr string, wsStreamHandler StreamHandler, metricsTracer pubsub.RawTracer) (*serviceImpl, error) {

	sm := makeStreamManager(ctx, log, h, wsStreamHandler, cfg.EnableGossipService)
	h.Network().Notify(sm)
	h.SetStreamHandler(AlgorandWsProtocol, sm.streamHandler)

	// set an empty handler for telemetryID/telemetryInstance protocol in order to allow other peers to know our telemetryID
	telemetryID := log.GetTelemetryGUID()
	telemetryInstance := log.GetInstanceName()
	telemetryProtoInfo := formatPeerTelemetryInfoProtocolName(telemetryID, telemetryInstance)
	h.SetStreamHandler(protocol.ID(telemetryProtoInfo), func(s network.Stream) { s.Close() })

	ps, err := makePubSub(ctx, cfg, h, metricsTracer)
	if err != nil {
		return nil, err
	}
	return &serviceImpl{
		log:        log,
		listenAddr: listenAddr,
		host:       h,
		streams:    sm,
		pubsub:     ps,
		pubsubCtx:  ctx,
		privKey:    h.Peerstore().PrivKey(h.ID()),
		topics:     make(map[string]*pubsub.Topic),
	}, nil
}

// Start starts the P2P service
func (s *serviceImpl) Start() error {
	if s.listenAddr == "" {
		// don't listen if no listen address configured
		return nil
	}

	listenAddr, err := multiaddr.NewMultiaddr(s.listenAddr)
	if err != nil {
		s.log.Errorf("failed to create multiaddress: %s", err)
		return err
	}

	return s.host.Network().Listen(listenAddr)
}

// Close shuts down the P2P service
func (s *serviceImpl) Close() error {
	return s.host.Close()
}

// ID returns the peer.ID for self
func (s *serviceImpl) ID() peer.ID {
	return s.host.ID()
}

// IDSigner returns a PeerIDChallengeSigner that implements the network identityChallengeSigner interface
func (s *serviceImpl) IDSigner() *PeerIDChallengeSigner {
	return &PeerIDChallengeSigner{key: s.privKey}
}

// DialPeersUntilTargetCount attempts to establish connections to the provided phonebook addresses
func (s *serviceImpl) DialPeersUntilTargetCount(targetConnCount int) {
	ps := s.host.Peerstore().(*pstore.PeerStore)
	addrInfos := ps.GetAddresses(targetConnCount, phonebook.PhoneBookEntryRelayRole)
	conns := s.host.Network().Conns()
	var numOutgoingConns int
	for _, conn := range conns {
		if conn.Stat().Direction == network.DirOutbound {
			numOutgoingConns++
		}
	}
	for _, peerInfo := range addrInfos {
		// if we are at our target count stop trying to connect
		if numOutgoingConns >= targetConnCount {
			return
		}
		// if we are already connected to this peer, skip it
		if len(s.host.Network().ConnsToPeer(peerInfo.ID)) > 0 {
			continue
		}
		err := s.dialNode(context.Background(), peerInfo) // leaving the calls as blocking for now, to not over-connect beyond fanout
		if err != nil {
			s.log.Warnf("failed to connect to peer %s: %v", peerInfo.ID, err)
		}
	}
}

// dialNode attempts to establish a connection to the provided peer
func (s *serviceImpl) dialNode(ctx context.Context, peer *peer.AddrInfo) error {
	// don't try connecting to ourselves
	if peer.ID == s.host.ID() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	return s.host.Connect(ctx, *peer)
}

// AddrInfo returns the peer.AddrInfo for self
func (s *serviceImpl) AddrInfo() peer.AddrInfo {
	addrs, err := s.host.Network().InterfaceListenAddresses()
	if err != nil {
		s.log.Errorf("failed to get listen addresses: %v", err)
	}
	return peer.AddrInfo{
		ID:    s.host.ID(),
		Addrs: addrs,
	}
}

// Conns returns the current connections
func (s *serviceImpl) Conns() []network.Conn {
	return s.host.Network().Conns()
}

// ClosePeer closes a connection to the provided peer
func (s *serviceImpl) ClosePeer(peer peer.ID) error {
	return s.host.Network().ClosePeer(peer)
}

// netAddressToListenAddress converts a netAddress in "ip:port" format to a listen address
// that can be passed in to libp2p.ListenAddrStrings
func netAddressToListenAddress(netAddress string) (string, error) {
	// split the string on ":"
	// if there are more than 2 parts, return an error
	parts := strings.Split(netAddress, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid netAddress %s; required format is \"ip:port\"", netAddress)
	}
	ip := "0.0.0.0"
	if parts[0] != "" {
		ip = parts[0]
	}
	if parts[1] == "" {
		return "", fmt.Errorf("invalid netAddress %s, port is required", netAddress)
	}

	return fmt.Sprintf("/ip4/%s/tcp/%s", ip, parts[1]), nil
}

// GetPeerTelemetryInfo returns the telemetry ID of a peer by looking at its protocols
func GetPeerTelemetryInfo(peerProtocols []protocol.ID) (telemetryID string, telemetryInstance string) {
	for _, protocol := range peerProtocols {
		if strings.HasPrefix(string(protocol), algorandGUIDProtocolPrefix) {
			telemetryInfo := string(protocol[len(algorandGUIDProtocolPrefix):])
			telemetryInfoParts := strings.Split(telemetryInfo, "/")
			if len(telemetryInfoParts) == 2 {
				telemetryIDBytes, err := base32.StdEncoding.DecodeString(telemetryInfoParts[0])
				if err == nil {
					telemetryID = string(telemetryIDBytes)
				}
				telemetryInstanceBytes, err := base32.StdEncoding.DecodeString(telemetryInfoParts[1])
				if err == nil {
					telemetryInstance = string(telemetryInstanceBytes)
				}
				return telemetryID, telemetryInstance
			}
		}
	}
	return "", ""
}

func formatPeerTelemetryInfoProtocolName(telemetryID string, telemetryInstance string) string {
	return fmt.Sprintf(algorandGUIDProtocolTemplate,
		base32.StdEncoding.EncodeToString([]byte(telemetryID)),
		base32.StdEncoding.EncodeToString([]byte(telemetryInstance)),
	)
}

var private6 = parseCIDR([]string{
	"100::/64",
	"2001:2::/48",
})

// parseCIDR converts string CIDRs to net.IPNet.
// function panics on errors so that it is only called during initialization.
func parseCIDR(cidrs []string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(cidrs))
	var ipnet *net.IPNet
	var err error
	for _, cidr := range cidrs {
		if _, ipnet, err = net.ParseCIDR(cidr); err != nil {
			panic(err)
		}
		result = append(result, ipnet)
	}
	return result
}

// addressFilter filters out private and unroutable addresses
func addressFilter(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	if logging.Base().IsLevelEnabled(logging.Debug) {
		var b strings.Builder
		for _, addr := range addrs {
			b.WriteRune(' ')
			b.WriteString(addr.String())
			b.WriteRune(' ')
		}
		logging.Base().Debugf("addressFilter input: %s", b.String())
	}

	res := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, addr := range addrs {
		if manet.IsPublicAddr(addr) {
			if _, err := addr.ValueForProtocol(multiaddr.P_IP4); err == nil {
				// no rules for IPv4 at the moment, accept
				res = append(res, addr)
				continue
			}

			isPrivate := false
			a, err := addr.ValueForProtocol(multiaddr.P_IP6)
			if err != nil {
				logging.Base().Warnf("failed to get IPv6 addr from %s: %v", addr, err)
				continue
			}
			addrIP := net.ParseIP(a)
			for _, ipnet := range private6 {
				if ipnet.Contains(addrIP) {
					isPrivate = true
					break
				}
			}
			if !isPrivate {
				res = append(res, addr)
			}
		}
	}
	if logging.Base().IsLevelEnabled(logging.Debug) {
		var b strings.Builder
		for _, addr := range res {
			b.WriteRune(' ')
			b.WriteString(addr.String())
			b.WriteRune(' ')
		}
		logging.Base().Debugf("addressFilter output: %s", b.String())
	}
	return res
}

// GetHTTPClient returns a libp2p-streaming http client that can be used to make requests to the given peer
func (s *serviceImpl) GetHTTPClient(addrInfo *peer.AddrInfo, connTimeStore limitcaller.ConnectionTimeStore, queueingTimeout time.Duration) (*http.Client, error) {
	return makeHTTPClientWithRateLimit(addrInfo, s, connTimeStore, queueingTimeout)
}
