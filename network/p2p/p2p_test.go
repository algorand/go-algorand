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
	"fmt"
	"net"
	"testing"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/network/p2p/peerstore"
	"github.com/algorand/go-algorand/network/phonebook"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// Tests the helper function netAddressToListenAddress which converts
// a config value netAddress to a multiaddress usable by libp2p.
func TestNetAddressToListenAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tests := []struct {
		input  string
		output string
		err    bool
	}{
		{
			input:  "192.168.1.1:8080",
			output: "/ip4/192.168.1.1/tcp/8080",
			err:    false,
		},
		{
			input:  ":8080",
			output: "/ip4/0.0.0.0/tcp/8080",
			err:    false,
		},
		{
			input:  "192.168.1.1:",
			output: "",
			err:    true,
		},
		{
			input:  "192.168.1.1",
			output: "",
			err:    true,
		},
		{
			input:  "192.168.1.1:8080:9090",
			output: "",
			err:    true,
		},
	}

	for _, test := range tests { //nolint:paralleltest
		t.Run(fmt.Sprintf("input: %s", test.input), func(t *testing.T) {
			res, err := netAddressToListenAddress(test.input)
			if test.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.output, res)
			}
		})
	}
}

func TestP2PPrivateAddresses(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	privAddrList := []string{
		"/ip4/10.0.0.0/ipcidr/8",
		"/ip4/100.64.0.0/ipcidr/10",
		"/ip4/169.254.0.0/ipcidr/16",
		"/ip4/172.16.0.0/ipcidr/12",
		"/ip4/192.0.0.0/ipcidr/24",
		"/ip4/192.0.2.0/ipcidr/24",
		"/ip4/192.88.99.0/ipcidr/24",
		"/ip4/192.168.0.0/ipcidr/16",
		"/ip4/198.18.0.0/ipcidr/15",
		"/ip4/198.51.100.0/ipcidr/24",
		"/ip4/203.0.113.0/ipcidr/24",
		"/ip4/224.0.0.0/ipcidr/4",
		"/ip4/224.0.0.0/ipcidr/4",
		"/ip4/233.252.0.0/ipcidr/4",
		"/ip4/255.255.255.255/ipcidr/32",
		"/ip6/fc00::/ipcidr/7",
		"/ip6/fe80::/ipcidr/10",
		"/ip6/2001:db8::/ipcidr/32",
	}

	// these are handled by addrFilter explicitly as a custom filter
	extra := []string{
		"/ip6/100::/ipcidr/64",
		"/ip6/2001:2::/ipcidr/48",
	}

	for _, addr := range privAddrList {
		ma := multiaddr.StringCast(addr)
		require.False(t, manet.IsPublicAddr(ma), "public check failed on %s", addr)
		require.Empty(t, addressFilter([]multiaddr.Multiaddr{ma}), "addrFilter failed on %s", addr)
	}

	for _, addr := range extra {
		ma := multiaddr.StringCast(addr)
		require.Empty(t, addressFilter([]multiaddr.Multiaddr{ma}), "addrFilter failed on %s", addr)
	}

	// ensure addrFilter allows normal addresses
	valid := []string{
		"/ip4/3.4.5.6/tcp/1234",
		"/ip6/2606:4700::/tcp/1234",
	}

	for _, addr := range valid {
		ma := multiaddr.StringCast(addr)
		require.Equal(t, []multiaddr.Multiaddr{ma}, addressFilter([]multiaddr.Multiaddr{ma}), "addrFilter failed on %s", addr)
	}
}

func TestP2PMaNetIsIPUnspecified(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	unspecified := []string{
		":0",
		":1234",
		"0.0.0.0:2345",
		"0.0.0.0:0",
	}
	for _, addr := range unspecified {
		parsed, err := netAddressToListenAddress(addr)
		require.NoError(t, err)
		require.True(t, manet.IsIPUnspecified(multiaddr.StringCast(parsed)), "expected %s to be unspecified", addr)
	}

	specified := []string{
		"127.0.0.1:0",
		"127.0.0.1:1234",
		"1.2.3.4:5678",
		"1.2.3.4:0",
		"192.168.0.111:0",
		"10.0.0.1:101",
	}
	for _, addr := range specified {
		parsed, err := netAddressToListenAddress(addr)
		require.NoError(t, err)
		require.False(t, manet.IsIPUnspecified(multiaddr.StringCast(parsed)), "expected %s to be specified", addr)
	}

	// also make sure IsIPUnspecified supports IPv6
	unspecified6 := []string{
		"/ip6/::/tcp/1234",
	}
	for _, addr := range unspecified6 {
		require.True(t, manet.IsIPUnspecified(multiaddr.StringCast(addr)), "expected %s to be unspecified", addr)
	}
}

// TestP2PMakeHostAddressFilter ensures that the host address filter is enabled only when the
// NetAddress is set to "all interfaces" value (0.0.0.0:P or :P)
func TestP2PMakeHostAddressFilter(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	td := t.TempDir()
	pstore, err := peerstore.NewPeerStore(nil, "test")
	require.NoError(t, err)

	// check "all interfaces" addr
	for _, addr := range []string{":0", "0.0.0.0:0"} {
		cfg := config.GetDefaultLocal()
		cfg.NetAddress = addr
		host, la, err := MakeHost(cfg, td, pstore)
		require.NoError(t, err)
		require.Equal(t, "/ip4/0.0.0.0/tcp/0", la)
		require.Empty(t, host.Addrs())

		mala, err := multiaddr.NewMultiaddr(la)
		require.NoError(t, err)
		host.Network().Listen(mala)
		addrs := host.Addrs()
		if len(addrs) > 0 {
			// CI servers might have a single public IP interface, validate if this is a case
			for _, a := range addrs {
				require.True(t, manet.IsPublicAddr(a))
			}
		}
		host.Close()
	}

	// check specific addresses IPv4 retrieved from the system
	addresses := []string{}
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		require.NoError(t, err)
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPAddr:
				if v.IP.To4() != nil {
					addresses = append(addresses, v.IP.String())
				}
			case *net.IPNet:
				if v.IP.To4() != nil {
					addresses = append(addresses, v.IP.String())
				}
			}
		}
	}
	for _, addr := range addresses {
		cfg := config.GetDefaultLocal()
		cfg.NetAddress = addr + ":0"
		host, la, err := MakeHost(cfg, td, pstore)
		require.NoError(t, err)
		require.Equal(t, "/ip4/"+addr+"/tcp/0", la)
		require.Empty(t, host.Addrs())
		mala, err := multiaddr.NewMultiaddr(la)
		require.NoError(t, err)
		err = host.Network().Listen(mala)
		require.NoError(t, err)
		require.NotEmpty(t, host.Addrs())
		host.Close()
	}
}

func TestP2PPubSubOptions(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var opts []pubsub.Option
	option := DisablePubSubPeerExchange()
	option(&opts)
	require.Len(t, opts, 1)

	tracer := &mockRawTracer{}
	option = SetPubSubMetricsTracer(tracer)
	option(&opts)
	require.Len(t, opts, 2)

	filterFunc := func(roleChecker peerstore.RoleChecker, pid peer.ID) bool {
		return roleChecker.HasRole(pid, phonebook.RelayRole)
	}
	checker := &mockRoleChecker{}
	option = SetPubSubPeerFilter(filterFunc, checker)
	option(&opts)
	require.Len(t, opts, 3)
}

type mockRawTracer struct{}

func (m *mockRawTracer) AddPeer(p peer.ID, proto protocol.ID)             {}
func (m *mockRawTracer) RemovePeer(p peer.ID)                             {}
func (m *mockRawTracer) Join(topic string)                                {}
func (m *mockRawTracer) Leave(topic string)                               {}
func (m *mockRawTracer) Graft(p peer.ID, topic string)                    {}
func (m *mockRawTracer) Prune(p peer.ID, topic string)                    {}
func (m *mockRawTracer) ValidateMessage(msg *pubsub.Message)              {}
func (m *mockRawTracer) DeliverMessage(msg *pubsub.Message)               {}
func (m *mockRawTracer) RejectMessage(msg *pubsub.Message, reason string) {}
func (m *mockRawTracer) DuplicateMessage(msg *pubsub.Message)             {}
func (m *mockRawTracer) ThrottlePeer(p peer.ID)                           {}
func (m *mockRawTracer) RecvRPC(rpc *pubsub.RPC)                          {}
func (m *mockRawTracer) SendRPC(rpc *pubsub.RPC, p peer.ID)               {}
func (m *mockRawTracer) DropRPC(rpc *pubsub.RPC, p peer.ID)               {}
func (m *mockRawTracer) UndeliverableMessage(msg *pubsub.Message)         {}

type mockRoleChecker struct{}

func (m *mockRoleChecker) HasRole(pid peer.ID, role phonebook.Role) bool {
	return true
}
