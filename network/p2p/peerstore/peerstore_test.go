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

package peerstore

import (
	"crypto/rand"
	"fmt"
	"math"
	"testing"
	"time"

	libp2p_crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2p "github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/network/phonebook"
	"github.com/algorand/go-algorand/test/partitiontest"
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
	ps, err := NewPeerStore(addrInfo, "net-id")
	require.NoError(t, err)
	defer ps.Close()

	// peerstore is initialized with addresses
	peers := ps.PeersWithAddrs()
	require.Equal(t, 4, len(peers))

	// add peer addresses
	var addrs []string
	var peerIDs []peer.ID
	for i := 0; i < 4; i++ {
		privKey, _, err := libp2p_crypto.GenerateEd25519Key(rand.Reader)
		require.NoError(t, err)
		peerID, err := peer.IDFromPrivateKey(privKey)
		require.NoError(t, err)
		peerIDs = append(peerIDs, peerID)
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
	ps.ClearAddrs(peerIDs[0])
	peers = ps.PeersWithAddrs()
	require.Equal(t, 7, len(peers))

}

func testPhonebookAll(t *testing.T, set []*peer.AddrInfo, ph *PeerStore) {
	actual := ph.GetAddresses(len(set), phonebook.RelayRole)
	for _, info := range actual {
		ok := false
		for _, known := range set {
			if info.ID == known.ID {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("get returned junk %#v", info)
		}
	}
	for _, known := range set {
		ok := false
		for _, info := range actual {
			if info.ID == known.ID {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("get missed %#v; actual=%#v; set=%#v", known, actual, set)
		}
	}
}

func testPhonebookUniform(t *testing.T, set []*peer.AddrInfo, ph *PeerStore, getsize int) {
	uniformityTestLength := 250000 / len(set)
	expected := (uniformityTestLength * getsize) / len(set)
	counts := make(map[string]int)
	for i := 0; i < len(set); i++ {
		counts[set[i].ID.String()] = 0
	}
	for i := 0; i < uniformityTestLength; i++ {
		actual := ph.GetAddresses(getsize, phonebook.RelayRole)
		for _, info := range actual {
			if _, ok := counts[info.ID.String()]; ok {
				counts[info.ID.String()]++
			}
		}
	}
	min, max := math.MaxInt, 0
	for _, count := range counts {
		if count > max {
			max = count
		}
		if count < min {
			min = count
		}
	}
	// TODO: what's a good probability-theoretic threshold for good enough?
	if max-min > (expected / 5) {
		t.Errorf("counts %#v", counts)
	}
}

func TestArrayPhonebookAll(t *testing.T) {
	partitiontest.PartitionTest(t)

	set := []string{"a:4041", "b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	infoSet := make([]*peer.AddrInfo, 0)
	for _, addr := range set {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoSet = append(infoSet, info)
	}

	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	for _, addr := range set {
		entry := makePhonebookEntryData("", phonebook.RelayRole, false)
		info, _ := peerInfoFromDomainPort(addr)
		ph.AddAddrs(info.ID, info.Addrs, libp2p.AddressTTL)
		ph.Put(info.ID, psmdkAddressData, entry)
	}
	testPhonebookAll(t, infoSet, ph)
}

func TestArrayPhonebookUniform1(t *testing.T) {
	partitiontest.PartitionTest(t)

	set := []string{"a:4041", "b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	infoSet := make([]*peer.AddrInfo, 0)
	for _, addr := range set {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoSet = append(infoSet, info)
	}

	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	for _, addr := range set {
		entry := makePhonebookEntryData("", phonebook.RelayRole, false)
		info, _ := peerInfoFromDomainPort(addr)
		ph.AddAddrs(info.ID, info.Addrs, libp2p.AddressTTL)
		ph.Put(info.ID, psmdkAddressData, entry)
	}
	testPhonebookUniform(t, infoSet, ph, 1)
}

func TestArrayPhonebookUniform3(t *testing.T) {
	partitiontest.PartitionTest(t)

	set := []string{"a:4041", "b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	infoSet := make([]*peer.AddrInfo, 0)
	for _, addr := range set {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoSet = append(infoSet, info)
	}

	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	for _, addr := range set {
		entry := makePhonebookEntryData("", phonebook.RelayRole, false)
		info, _ := peerInfoFromDomainPort(addr)
		ph.AddAddrs(info.ID, info.Addrs, libp2p.AddressTTL)
		ph.Put(info.ID, psmdkAddressData, entry)
	}
	testPhonebookUniform(t, infoSet, ph, 3)
}

func TestMultiPhonebook(t *testing.T) {
	partitiontest.PartitionTest(t)

	set := []string{"a:4041", "b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	infoSet := make([]*peer.AddrInfo, 0)
	for _, addr := range set {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoSet = append(infoSet, info)
	}
	pha := append([]*peer.AddrInfo{}, infoSet[:5]...)
	phb := append([]*peer.AddrInfo{}, infoSet[5:]...)
	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	ph.ReplacePeerList(pha, "pha", phonebook.RelayRole)
	ph.ReplacePeerList(phb, "phb", phonebook.RelayRole)

	testPhonebookAll(t, infoSet, ph)
	testPhonebookUniform(t, infoSet, ph, 1)
	testPhonebookUniform(t, infoSet, ph, 3)
}

// TestMultiPhonebookPersistentPeers validates that the peers added via Phonebook.AddPersistentPeers
// are not replaced when Phonebook.ReplacePeerList is called
func TestMultiPhonebookPersistentPeers(t *testing.T) {
	partitiontest.PartitionTest(t)

	info, err := peerInfoFromDomainPort("a:4041")
	require.NoError(t, err)
	persistentPeers := []*peer.AddrInfo{info}
	set := []string{"b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	infoSet := make([]*peer.AddrInfo, 0)
	for _, addr := range set {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoSet = append(infoSet, info)
	}

	pha := append([]*peer.AddrInfo{}, infoSet[:5]...)
	phb := append([]*peer.AddrInfo{}, infoSet[5:]...)
	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	ph.AddPersistentPeers(persistentPeers, "pha", phonebook.RelayRole)
	ph.AddPersistentPeers(persistentPeers, "phb", phonebook.RelayRole)
	ph.ReplacePeerList(pha, "pha", phonebook.RelayRole)
	ph.ReplacePeerList(phb, "phb", phonebook.RelayRole)

	testPhonebookAll(t, append(infoSet, info), ph)
	allAddresses := ph.GetAddresses(len(set)+len(persistentPeers), phonebook.RelayRole)
	for _, pp := range persistentPeers {
		found := false
		for _, addr := range allAddresses {
			if addr.ID == pp.ID {
				found = true
				break
			}
		}
		require.True(t, found, fmt.Sprintf("%s not found in %v", string(pp.ID), allAddresses))
	}

	// check that role of persistent peer gets updated with AddPersistentPeers
	ph2, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	ph2.AddPersistentPeers(persistentPeers, "phc", phonebook.RelayRole)
	ph2.AddPersistentPeers(persistentPeers, "phc", phonebook.ArchivalRole)
	allAddresses = ph2.GetAddresses(len(set)+len(persistentPeers), phonebook.RelayRole)
	require.Len(t, allAddresses, 1)
	allAddresses = ph2.GetAddresses(len(set)+len(persistentPeers), phonebook.ArchivalRole)
	require.Len(t, allAddresses, 1)

	// check that role of persistent peer survives
	ph3, err := MakePhonebook(1, 1*time.Millisecond)
	ph3.AddPersistentPeers(persistentPeers, "phc", phonebook.ArchivalRole)
	require.NoError(t, err)
	phc := []*peer.AddrInfo{info}
	ph3.ReplacePeerList(phc, "phc", phonebook.RelayRole)

	allAddresses = ph3.GetAddresses(len(set)+len(persistentPeers), phonebook.RelayRole)
	require.Len(t, allAddresses, 1)
	allAddresses = ph3.GetAddresses(len(set)+len(persistentPeers), phonebook.ArchivalRole)
	require.Len(t, allAddresses, 1)

}

func TestMultiPhonebookDuplicateFiltering(t *testing.T) {
	partitiontest.PartitionTest(t)

	set := []string{"b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	infoSet := make([]*peer.AddrInfo, 0)
	for _, addr := range set {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoSet = append(infoSet, info)
	}

	pha := append([]*peer.AddrInfo{}, infoSet[:7]...)
	phb := append([]*peer.AddrInfo{}, infoSet[3:]...)
	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	ph.ReplacePeerList(pha, "pha", phonebook.RelayRole)
	ph.ReplacePeerList(phb, "phb", phonebook.RelayRole)

	testPhonebookAll(t, infoSet, ph)
	testPhonebookUniform(t, infoSet, ph, 1)
	testPhonebookUniform(t, infoSet, ph, 3)
}

func TestWaitAndAddConnectionTimeLongtWindow(t *testing.T) {
	partitiontest.PartitionTest(t)

	// make the connectionsRateLimitingWindow long enough to avoid triggering it when the
	// test is running in a slow environment
	// The test will artificially simulate time passing
	timeUnit := 2000 * time.Second
	connectionsRateLimitingWindow := 2 * timeUnit
	entries, err := MakePhonebook(3, connectionsRateLimitingWindow)
	require.NoError(t, err)
	addr1 := "addrABC:4040"
	addr2 := "addrXYZ:4041"
	info1, _ := peerInfoFromDomainPort(addr1)
	info2, _ := peerInfoFromDomainPort(addr2)

	// Address not in. Should return false
	addrInPhonebook, _, provisionalTime := entries.GetConnectionWaitTime(string(info1.ID))
	require.Equal(t, false, addrInPhonebook)
	require.Equal(t, false, entries.UpdateConnectionTime(string(info1.ID), provisionalTime))

	// Test the addresses are populated in the phonebook and a
	// time can be added to one of them
	entries.ReplacePeerList([]*peer.AddrInfo{info1, info2}, "default", phonebook.RelayRole)
	addrInPhonebook, waitTime, provisionalTime := entries.GetConnectionWaitTime(string(info1.ID))
	require.Equal(t, true, addrInPhonebook)
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(string(info1.ID), provisionalTime))
	data, _ := entries.Get(info1.ID, psmdkAddressData)
	require.NotNil(t, data)
	ad := data.(addressData)
	phBookData := ad.recentConnectionTimes
	require.Equal(t, 1, len(phBookData))

	// simulate passing a unit of time
	for rct := range phBookData {
		phBookData[rct] = phBookData[rct].Add(-1 * timeUnit)
	}

	// add another value to addr
	_, waitTime, provisionalTime = entries.GetConnectionWaitTime(string(info1.ID))
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(string(info1.ID), provisionalTime))
	data, _ = entries.Get(info1.ID, psmdkAddressData)
	ad = data.(addressData)
	phBookData = ad.recentConnectionTimes
	require.Equal(t, 2, len(phBookData))

	// simulate passing a unit of time
	for rct := range phBookData {
		phBookData[rct] = phBookData[rct].Add(-1 * timeUnit)
	}

	// the first time should be removed and a new one added
	// there should not be any wait
	_, waitTime, provisionalTime = entries.GetConnectionWaitTime(string(info1.ID))
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(string(info1.ID), provisionalTime))
	data, _ = entries.Get(info1.ID, psmdkAddressData)
	ad = data.(addressData)
	phBookData2 := ad.recentConnectionTimes
	require.Equal(t, 2, len(phBookData2))

	// make sure the right time was removed
	require.Equal(t, phBookData[1], phBookData2[0])
	require.Equal(t, true, phBookData2[0].Before(phBookData2[1]))

	// try requesting from another address, make sure
	// a separate array is used for these new requests

	// add 3 values to another address. should not wait
	// value 1
	_, waitTime, provisionalTime = entries.GetConnectionWaitTime(string(info2.ID))
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(string(info2.ID), provisionalTime))

	// introduce a gap between the two requests so that only the first will be removed later when waited
	// simulate passing a unit of time
	data2, _ := entries.Get(info2.ID, psmdkAddressData)
	require.NotNil(t, data2)
	ad2 := data2.(addressData)
	for rct := range ad2.recentConnectionTimes {
		ad2.recentConnectionTimes[rct] = ad2.recentConnectionTimes[rct].Add(-1 * timeUnit)
	}

	// value 2
	_, waitTime, provisionalTime = entries.GetConnectionWaitTime(string(info2.ID))
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(string(info2.ID), provisionalTime))
	// value 3
	_, waitTime, provisionalTime = entries.GetConnectionWaitTime(string(info2.ID))
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(string(info2.ID), provisionalTime))

	data2, _ = entries.Get(info2.ID, psmdkAddressData)
	ad2 = data2.(addressData)
	phBookData = ad2.recentConnectionTimes
	// all three times should be queued
	require.Equal(t, 3, len(phBookData))

	// add another element to trigger wait
	_, waitTime, _ = entries.GetConnectionWaitTime(string(info2.ID))
	require.Greater(t, int64(waitTime), int64(0))
	// no element should be removed
	data2, _ = entries.Get(info2.ID, psmdkAddressData)
	ad2 = data2.(addressData)
	phBookData2 = ad2.recentConnectionTimes
	require.Equal(t, phBookData[0], phBookData2[0])
	require.Equal(t, phBookData[1], phBookData2[1])
	require.Equal(t, phBookData[2], phBookData2[2])
	// simulate passing of the waitTime duration
	for rct := range ad2.recentConnectionTimes {
		ad2.recentConnectionTimes[rct] = ad2.recentConnectionTimes[rct].Add(-1 * waitTime)
	}

	// The wait should be sufficient
	_, waitTime, provisionalTime = entries.GetConnectionWaitTime(string(info2.ID))
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(string(info2.ID), provisionalTime))
	// only one element should be removed, and one added
	data2, _ = entries.Get(info2.ID, psmdkAddressData)
	ad2 = data2.(addressData)
	phBookData2 = ad2.recentConnectionTimes
	require.Equal(t, 3, len(phBookData2))

	// make sure the right time was removed
	require.Equal(t, phBookData[1], phBookData2[0])
	require.Equal(t, phBookData[2], phBookData2[1])
}

// TestPhonebookRoles tests that the filtering by roles for different
// phonebooks entries works as expected.
func TestPhonebookRoles(t *testing.T) {
	partitiontest.PartitionTest(t)

	relaysSet := []string{"relay1:4040", "relay2:4041", "relay3:4042"}
	archiverSet := []string{"archiver1:1111", "archiver2:1112", "archiver3:1113"}

	infoRelaySet := make([]*peer.AddrInfo, 0)
	for _, addr := range relaysSet {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoRelaySet = append(infoRelaySet, info)
	}

	infoArchiverSet := make([]*peer.AddrInfo, 0)
	for _, addr := range archiverSet {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoArchiverSet = append(infoArchiverSet, info)
	}

	ph, err := MakePhonebook(1, 1)
	require.NoError(t, err)
	ph.ReplacePeerList(infoRelaySet, "default", phonebook.RelayRole)
	ph.ReplacePeerList(infoArchiverSet, "default", phonebook.ArchivalRole)
	require.Equal(t, len(relaysSet)+len(archiverSet), len(ph.Peers()))
	require.Equal(t, len(relaysSet)+len(archiverSet), ph.Length())

	for _, role := range []phonebook.Role{phonebook.RelayRole, phonebook.ArchivalRole} {
		for k := 0; k < 100; k++ {
			for l := 0; l < 3; l++ {
				entries := ph.GetAddresses(l, role)
				if role == phonebook.RelayRole {
					for _, entry := range entries {
						require.Contains(t, string(entry.ID), "relay")
					}
				} else if role == phonebook.ArchivalRole {
					for _, entry := range entries {
						require.Contains(t, string(entry.ID), "archiver")
					}
				}
			}
		}
	}
}

// TestPhonebookRolesMulti makes sure the same host might have multiple roles
func TestPhonebookRolesMulti(t *testing.T) {
	partitiontest.PartitionTest(t)

	relaysSet := []string{"relay1:4040", "relay2:4041"}
	archiverSet := []string{"relay1:4040", "archiver1:1111"}
	const numUnique = 3

	infoRelaySet := make([]*peer.AddrInfo, 0)
	for _, addr := range relaysSet {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoRelaySet = append(infoRelaySet, info)
	}

	infoArchiverSet := make([]*peer.AddrInfo, 0)
	for _, addr := range archiverSet {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoArchiverSet = append(infoArchiverSet, info)
	}

	ph, err := MakePhonebook(1, 1)
	require.NoError(t, err)
	ph.ReplacePeerList(infoRelaySet, "default", phonebook.RelayRole)
	ph.ReplacePeerList(infoArchiverSet, "default", phonebook.ArchivalRole)
	require.Equal(t, numUnique, len(ph.Peers()))
	require.Equal(t, numUnique, ph.Length())

	const maxPeers = 5
	entries := ph.GetAddresses(maxPeers, phonebook.RelayRole)
	require.Equal(t, len(relaysSet), len(entries))
	entries = ph.GetAddresses(maxPeers, phonebook.ArchivalRole)
	require.Equal(t, len(archiverSet), len(entries))
}

func TestReplacePeerList(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	relaysSet := []string{"a:1", "b:2"}
	archiverSet := []string{"c:3"}
	comboSet := []string{"b:2", "c:3"} // b is in both sets

	infoRelaySet := make([]*peer.AddrInfo, 0)
	for _, addr := range relaysSet {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoRelaySet = append(infoRelaySet, info)
	}

	infoArchiverSet := make([]*peer.AddrInfo, 0)
	for _, addr := range archiverSet {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoArchiverSet = append(infoArchiverSet, info)
	}

	infoComboArchiverSet := make([]*peer.AddrInfo, 0)
	for _, addr := range comboSet {
		info, err := peerInfoFromDomainPort(addr)
		require.NoError(t, err)
		infoComboArchiverSet = append(infoComboArchiverSet, info)
	}

	ph, err := MakePhonebook(1, 1)
	require.NoError(t, err)

	ph.ReplacePeerList(infoRelaySet, "default", phonebook.RelayRole)
	res := ph.GetAddresses(4, phonebook.RelayRole)
	require.Equal(t, 2, len(res))
	for _, info := range infoRelaySet {
		require.Contains(t, res, info)
	}

	ph.ReplacePeerList(infoArchiverSet, "default", phonebook.ArchivalRole)
	res = ph.GetAddresses(4, phonebook.ArchivalRole)
	require.Equal(t, 1, len(res))
	for _, info := range infoArchiverSet {
		require.Contains(t, res, info)
	}

	// make b archival in addition to relay
	ph.ReplacePeerList(infoComboArchiverSet, "default", phonebook.ArchivalRole)
	res = ph.GetAddresses(4, phonebook.RelayRole)
	require.Equal(t, 2, len(res))
	for _, info := range infoRelaySet {
		require.Contains(t, res, info)
	}
	res = ph.GetAddresses(4, phonebook.ArchivalRole)
	require.Equal(t, 2, len(res))
	for _, info := range infoComboArchiverSet {
		require.Contains(t, res, info)
	}

	// update relays
	ph.ReplacePeerList(infoRelaySet, "default", phonebook.RelayRole)
	res = ph.GetAddresses(4, phonebook.RelayRole)
	require.Equal(t, 2, len(res))
	for _, info := range infoRelaySet {
		require.Contains(t, res, info)
	}
	res = ph.GetAddresses(4, phonebook.ArchivalRole)
	require.Equal(t, 2, len(res))
	for _, info := range infoComboArchiverSet {
		require.Contains(t, res, info)
	}

	// exclude b from archival
	ph.ReplacePeerList(infoArchiverSet, "default", phonebook.ArchivalRole)
	res = ph.GetAddresses(4, phonebook.RelayRole)
	require.Equal(t, 2, len(res))
	for _, info := range infoRelaySet {
		require.Contains(t, res, info)
	}
	res = ph.GetAddresses(4, phonebook.ArchivalRole)
	require.Equal(t, 1, len(res))
	for _, info := range infoArchiverSet {
		require.Contains(t, res, info)
	}
}
