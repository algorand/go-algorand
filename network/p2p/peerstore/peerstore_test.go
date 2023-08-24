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
	"time"

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

	set := []string{"a:4041", "b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	var peerIDs []string
	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	for _, addr := range set {
		entry := makePhonebookEntryData("", network.PhoneBookEntryRelayRole, false)
		info, _ := PeerInfoFromDomainPort(addr)
		peerIDs = append(peerIDs, info.ID.String())
		ph.AddAddrs(info.ID, info.Addrs, libp2p.AddressTTL)
		ph.Put(info.ID, "addressData", entry)
	}
	testPhonebookAll(t, peerIDs, ph)
}

func TestArrayPhonebookUniform1(t *testing.T) {
	partitiontest.PartitionTest(t)

	set := []string{"a:4041", "b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	var peerIDs []string
	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	for _, addr := range set {
		entry := makePhonebookEntryData("", network.PhoneBookEntryRelayRole, false)
		info, _ := PeerInfoFromDomainPort(addr)
		peerIDs = append(peerIDs, info.ID.String())
		ph.AddAddrs(info.ID, info.Addrs, libp2p.AddressTTL)
		ph.Put(info.ID, "addressData", entry)
	}
	testPhonebookUniform(t, peerIDs, ph, 1)
}

func TestArrayPhonebookUniform3(t *testing.T) {
	partitiontest.PartitionTest(t)

	set := []string{"a:4041", "b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	var peerIDs []string
	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	for _, addr := range set {
		entry := makePhonebookEntryData("", network.PhoneBookEntryRelayRole, false)
		info, _ := PeerInfoFromDomainPort(addr)
		peerIDs = append(peerIDs, info.ID.String())
		ph.AddAddrs(info.ID, info.Addrs, libp2p.AddressTTL)
		ph.Put(info.ID, "addressData", entry)
	}
	testPhonebookUniform(t, peerIDs, ph, 3)
}

func TestMultiPhonebook(t *testing.T) {
	partitiontest.PartitionTest(t)

	set := []string{"a:4041", "b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	var peerIDs []string
	pha := make([]string, 0)
	for _, e := range set[:5] {
		info, _ := PeerInfoFromDomainPort(e)
		peerIDs = append(peerIDs, info.ID.String())
		pha = append(pha, e)
	}
	phb := make([]string, 0)
	for _, e := range set[5:] {
		info, _ := PeerInfoFromDomainPort(e)
		peerIDs = append(peerIDs, info.ID.String())
		phb = append(phb, e)
	}

	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	ph.ReplacePeerList(pha, "pha", network.PhoneBookEntryRelayRole)
	ph.ReplacePeerList(phb, "phb", network.PhoneBookEntryRelayRole)

	testPhonebookAll(t, peerIDs, ph)
	testPhonebookUniform(t, peerIDs, ph, 1)
	testPhonebookUniform(t, peerIDs, ph, 3)
}

// TestMultiPhonebookPersistentPeers validates that the peers added via Phonebook.AddPersistentPeers
// are not replaced when Phonebook.ReplacePeerList is called
func TestMultiPhonebookPersistentPeers(t *testing.T) {
	partitiontest.PartitionTest(t)

	persistentPeers := []string{"a:4041"}
	var persistentPeerIDs []string
	for _, pp := range persistentPeers {
		info, _ := PeerInfoFromDomainPort(pp)
		persistentPeerIDs = append(persistentPeerIDs, info.ID.String())
	}
	set := []string{"b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	var peerIDs []string
	pha := make([]string, 0)
	for _, e := range set[:5] {
		info, _ := PeerInfoFromDomainPort(e)
		peerIDs = append(peerIDs, info.ID.String())
		pha = append(pha, e)
	}
	phb := make([]string, 0)
	for _, e := range set[5:] {
		info, _ := PeerInfoFromDomainPort(e)
		peerIDs = append(peerIDs, info.ID.String())
		phb = append(phb, e)
	}
	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	ph.AddPersistentPeers(persistentPeers, "pha", network.PhoneBookEntryRelayRole)
	ph.AddPersistentPeers(persistentPeers, "phb", network.PhoneBookEntryRelayRole)
	ph.ReplacePeerList(pha, "pha", network.PhoneBookEntryRelayRole)
	ph.ReplacePeerList(phb, "phb", network.PhoneBookEntryRelayRole)

	testPhonebookAll(t, append(peerIDs, persistentPeerIDs...), ph)
	allAddresses := ph.GetAddresses(len(set)+len(persistentPeers), network.PhoneBookEntryRelayRole)
	for _, pp := range persistentPeerIDs {
		require.Contains(t, allAddresses, pp)
	}
}
