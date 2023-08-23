// Copyright (C) 2019-2023 Algorand, Inc.
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

package peerstore

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/test/partitiontest"
	libp2p_crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2p "github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
)

func TestPeerstore(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	peerAddrs := []string{
		"/dns4/ams-2.bootstrap.libp2p.io/tcp/443/wss/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
		"/ip4/147.75.83.83/tcp/4001/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Na",
		"/ip6/2604:1380:2000:7a00::1/udp/4001/quic/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj73Nb",
		"/ip4/198.51.100.0/tcp/4242/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
	}

	addrInfo, _ := PeerInfoFromAddrs(peerAddrs)
	ps, err := NewPeerStore(addrInfo)
	require.NoError(t, err)
	defer ps.Close()

	// peerstore is initialized with addresses
	peers := ps.PeersWithAddrs()
	require.Equal(t, 4, len(peers))

	// add peer addresses
	var addrs []string
	var peerIDS []peer.ID
	for i := 0; i < 4; i++ {
		privKey, _, err := libp2p_crypto.GenerateEd25519Key(rand.Reader)
		require.NoError(t, err)
		peerID, err := peer.IDFromPrivateKey(privKey)
		require.NoError(t, err)
		peerIDS = append(peerIDS, peerID)
		maddrStr := fmt.Sprintf("/ip4/1.2.3.4/tcp/%d/p2p/%s", 4000+i, peerID.String())
		addrs = append(addrs, maddrStr)
	}
	addrInfo, _ = PeerInfoFromAddrs(addrs)
	require.NoError(t, err)
	for i := 0; i < len(addrInfo); i++ {
		info := addrInfo[i]
		ps.AddAddrs(info.ID, info.Addrs, libp2p.PermanentAddrTTL)
	}

	// peerstore should have 6 peers now
	peers = ps.PeersWithAddrs()
	require.Equal(t, 8, len(peers))

	// remove a peer addr
	ps.ClearAddrs(peerIDS[0])
	peers = ps.PeersWithAddrs()
	require.Equal(t, 7, len(peers))

}

func testPhonebookAll(t *testing.T, set []string, ph network.Phonebook) {
	actual := ph.GetAddresses(len(set), network.PhoneBookEntryRelayRole)
	for _, got := range actual {
		ok := false
		for _, known := range set {
			if got == known {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("get returned junk %#v", got)
		}
	}
	for _, known := range set {
		ok := false
		for _, got := range actual {
			if got == known {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("get missed %#v; actual=%#v; set=%#v", known, actual, set)
		}
	}
}

func testPhonebookUniform(t *testing.T, set []string, ph network.Phonebook, getsize int) {
	uniformityTestLength := 250000 / len(set)
	expected := (uniformityTestLength * getsize) / len(set)
	counts := make([]int, len(set))
	for i := 0; i < uniformityTestLength; i++ {
		actual := ph.GetAddresses(getsize, network.PhoneBookEntryRelayRole)
		for i, known := range set {
			for _, xa := range actual {
				if known == xa {
					counts[i]++
				}
			}
		}
	}
	min := counts[0]
	max := counts[0]
	for i := 1; i < len(counts); i++ {
		if counts[i] > max {
			max = counts[i]
		}
		if counts[i] < min {
			min = counts[i]
		}
	}
	// TODO: what's a good probability-theoretic threshold for good enough?
	if max-min > (expected / 5) {
		t.Errorf("counts %#v", counts)
	}
}

func generateMultiAddrs(n int) ([]string, []string) {
	var multiaddrs []string
	var ids []string

	for i := 0; i < n; i++ {
		privKey, _, _ := libp2p_crypto.GenerateEd25519Key(rand.Reader)
		peerID, _ := peer.IDFromPrivateKey(privKey)
		ids = append(ids, peerID.String())
		multiaddrs = append(multiaddrs, fmt.Sprintf("/ip4/198.51.100.0/tcp/4242/p2p/%s", peerID.String()))

	}
	return multiaddrs, ids
}
func TestArrayPhonebookAll(t *testing.T) {
	partitiontest.PartitionTest(t)

	multiaddrs, ids := generateMultiAddrs(10)
	addrs, _ := PeerInfoFromAddrs(multiaddrs)
	ps, err := NewPeerStore(addrs)
	require.NoError(t, err)
	for _, id := range ids {
		entry := makePhonebookEntryData("", network.PhoneBookEntryRelayRole, false)
		peerid, err := peer.Decode(id)
		require.NoError(t, err)
		ps.Put(peerid, "addressData", entry)
	}
	testPhonebookAll(t, ids, ps)
}

func TestArrayPhonebookUniform1(t *testing.T) {
	partitiontest.PartitionTest(t)

	multiaddrs, ids := generateMultiAddrs(10)
	addrs, _ := PeerInfoFromAddrs(multiaddrs)
	ps, _ := NewPeerStore(addrs)
	for _, id := range ids {
		entry := makePhonebookEntryData("", network.PhoneBookEntryRelayRole, false)
		peerid, err := peer.Decode(id)
		require.NoError(t, err)
		ps.Put(peerid, "addressData", entry)
	}
	testPhonebookUniform(t, ids, ps, 1)
}

func TestArrayPhonebookUniform3(t *testing.T) {
	partitiontest.PartitionTest(t)

	multiaddrs, ids := generateMultiAddrs(10)
	addrs, _ := PeerInfoFromAddrs(multiaddrs)
	ps, _ := NewPeerStore(addrs)
	for _, id := range ids {
		entry := makePhonebookEntryData("", network.PhoneBookEntryRelayRole, false)
		peerid, err := peer.Decode(id)
		require.NoError(t, err)
		ps.Put(peerid, "addressData", entry)
	}
	testPhonebookUniform(t, ids, ps, 3)
}

func TestMultiPhonebook(t *testing.T) {
	partitiontest.PartitionTest(t)

	multiaddrs, ids := generateMultiAddrs(10)
	addrs, _ := PeerInfoFromAddrs(multiaddrs)
	pha := make([]string, 0)
	for _, e := range multiaddrs[:5] {
		pha = append(pha, e)
	}
	phb := make([]string, 0)
	for _, e := range multiaddrs[5:] {
		phb = append(phb, e)
	}

	ps, _ := NewPeerStore(addrs)
	ps.ReplacePeerList(pha, "pha", network.PhoneBookEntryRelayRole)
	ps.ReplacePeerList(phb, "phb", network.PhoneBookEntryRelayRole)

	testPhonebookAll(t, ids, ps)
	testPhonebookUniform(t, ids, ps, 1)
	testPhonebookUniform(t, ids, ps, 3)
}
