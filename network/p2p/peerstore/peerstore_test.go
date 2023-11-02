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
	"math"
	"testing"
	"time"

	libp2p_crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2p "github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// PhoneBookEntryRelayRole used for all the relays that are provided either via the algobootstrap SRV record
// or via a configuration file.
const PhoneBookEntryRelayRole = 1

// PhoneBookEntryArchiverRole used for all the archivers that are provided via the archive SRV record.
const PhoneBookEntryArchiverRole = 2

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

func testPhonebookAll(t *testing.T, set []string, ph *PeerStore) {
	actual := ph.GetAddresses(len(set), PhoneBookEntryRelayRole)
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

func testPhonebookUniform(t *testing.T, set []string, ph *PeerStore, getsize int) {
	uniformityTestLength := 250000 / len(set)
	expected := (uniformityTestLength * getsize) / len(set)
	counts := make(map[string]int)
	for i := 0; i < len(set); i++ {
		counts[set[i]] = 0
	}
	for i := 0; i < uniformityTestLength; i++ {
		actual := ph.GetAddresses(getsize, PhoneBookEntryRelayRole)
		for _, xa := range actual {
			if _, ok := counts[xa]; ok {
				counts[xa]++
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
	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	for _, addr := range set {
		entry := makePhonebookEntryData("", PhoneBookEntryRelayRole, false)
		info, _ := PeerInfoFromDomainPort(addr)
		ph.AddAddrs(info.ID, info.Addrs, libp2p.AddressTTL)
		ph.Put(info.ID, addressDataKey, entry)
	}
	testPhonebookAll(t, set, ph)
}

func TestArrayPhonebookUniform1(t *testing.T) {
	partitiontest.PartitionTest(t)

	set := []string{"a:4041", "b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	for _, addr := range set {
		entry := makePhonebookEntryData("", PhoneBookEntryRelayRole, false)
		info, _ := PeerInfoFromDomainPort(addr)
		ph.AddAddrs(info.ID, info.Addrs, libp2p.AddressTTL)
		ph.Put(info.ID, addressDataKey, entry)
	}
	testPhonebookUniform(t, set, ph, 1)
}

func TestArrayPhonebookUniform3(t *testing.T) {
	partitiontest.PartitionTest(t)

	set := []string{"a:4041", "b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	for _, addr := range set {
		entry := makePhonebookEntryData("", PhoneBookEntryRelayRole, false)
		info, _ := PeerInfoFromDomainPort(addr)
		ph.AddAddrs(info.ID, info.Addrs, libp2p.AddressTTL)
		ph.Put(info.ID, addressDataKey, entry)
	}
	testPhonebookUniform(t, set, ph, 3)
}

func TestMultiPhonebook(t *testing.T) {
	partitiontest.PartitionTest(t)

	set := []string{"a:4041", "b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	pha := make([]string, 0)
	for _, e := range set[:5] {
		pha = append(pha, e)
	}
	phb := make([]string, 0)
	for _, e := range set[5:] {
		phb = append(phb, e)
	}

	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	ph.ReplacePeerList(pha, "pha", PhoneBookEntryRelayRole)
	ph.ReplacePeerList(phb, "phb", PhoneBookEntryRelayRole)

	testPhonebookAll(t, set, ph)
	testPhonebookUniform(t, set, ph, 1)
	testPhonebookUniform(t, set, ph, 3)
}

// TestMultiPhonebookPersistentPeers validates that the peers added via Phonebook.AddPersistentPeers
// are not replaced when Phonebook.ReplacePeerList is called
func TestMultiPhonebookPersistentPeers(t *testing.T) {
	partitiontest.PartitionTest(t)

	persistentPeers := []string{"a:4041"}
	set := []string{"b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	pha := make([]string, 0)
	for _, e := range set[:5] {
		pha = append(pha, e)
	}
	phb := make([]string, 0)
	for _, e := range set[5:] {
		phb = append(phb, e)
	}
	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	ph.AddPersistentPeers(persistentPeers, "pha", PhoneBookEntryRelayRole)
	ph.AddPersistentPeers(persistentPeers, "phb", PhoneBookEntryRelayRole)
	ph.ReplacePeerList(pha, "pha", PhoneBookEntryRelayRole)
	ph.ReplacePeerList(phb, "phb", PhoneBookEntryRelayRole)

	testPhonebookAll(t, append(set, persistentPeers...), ph)
	allAddresses := ph.GetAddresses(len(set)+len(persistentPeers), PhoneBookEntryRelayRole)
	for _, pp := range persistentPeers {
		require.Contains(t, allAddresses, pp)
	}
}

func TestMultiPhonebookDuplicateFiltering(t *testing.T) {
	partitiontest.PartitionTest(t)

	set := []string{"b:4042", "c:4043", "d:4044", "e:4045", "f:4046", "g:4047", "h:4048", "i:4049", "j:4010"}
	pha := make([]string, 0)
	for _, e := range set[:7] {
		pha = append(pha, e)
	}
	phb := make([]string, 0)
	for _, e := range set[3:] {
		phb = append(phb, e)
	}
	ph, err := MakePhonebook(1, 1*time.Millisecond)
	require.NoError(t, err)
	ph.ReplacePeerList(pha, "pha", PhoneBookEntryRelayRole)
	ph.ReplacePeerList(phb, "phb", PhoneBookEntryRelayRole)

	testPhonebookAll(t, set, ph)
	testPhonebookUniform(t, set, ph, 1)
	testPhonebookUniform(t, set, ph, 3)
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
	info1, _ := PeerInfoFromDomainPort(addr1)
	info2, _ := PeerInfoFromDomainPort(addr2)

	// Address not in. Should return false
	addrInPhonebook, _, provisionalTime := entries.GetConnectionWaitTime(addr1)
	require.Equal(t, false, addrInPhonebook)
	require.Equal(t, false, entries.UpdateConnectionTime(addr1, provisionalTime))

	// Test the addresses are populated in the phonebook and a
	// time can be added to one of them
	entries.ReplacePeerList([]string{addr1, addr2}, "default", PhoneBookEntryRelayRole)
	addrInPhonebook, waitTime, provisionalTime := entries.GetConnectionWaitTime(addr1)
	require.Equal(t, true, addrInPhonebook)
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(addr1, provisionalTime))
	data, _ := entries.Get(info1.ID, addressDataKey)
	require.NotNil(t, data)
	ad := data.(addressData)
	phBookData := ad.recentConnectionTimes
	require.Equal(t, 1, len(phBookData))

	// simulate passing a unit of time
	for rct := range phBookData {
		phBookData[rct] = phBookData[rct].Add(-1 * timeUnit)
	}

	// add another value to addr
	addrInPhonebook, waitTime, provisionalTime = entries.GetConnectionWaitTime(addr1)
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(addr1, provisionalTime))
	data, _ = entries.Get(info1.ID, addressDataKey)
	ad = data.(addressData)
	phBookData = ad.recentConnectionTimes
	require.Equal(t, 2, len(phBookData))

	// simulate passing a unit of time
	for rct := range phBookData {
		phBookData[rct] = phBookData[rct].Add(-1 * timeUnit)
	}

	// the first time should be removed and a new one added
	// there should not be any wait
	addrInPhonebook, waitTime, provisionalTime = entries.GetConnectionWaitTime(addr1)
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(addr1, provisionalTime))
	data, _ = entries.Get(info1.ID, addressDataKey)
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
	_, waitTime, provisionalTime = entries.GetConnectionWaitTime(addr2)
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(addr2, provisionalTime))

	// introduce a gap between the two requests so that only the first will be removed later when waited
	// simulate passing a unit of time
	data2, _ := entries.Get(info2.ID, addressDataKey)
	require.NotNil(t, data2)
	ad2 := data2.(addressData)
	for rct := range ad2.recentConnectionTimes {
		ad2.recentConnectionTimes[rct] = ad2.recentConnectionTimes[rct].Add(-1 * timeUnit)
	}

	// value 2
	_, waitTime, provisionalTime = entries.GetConnectionWaitTime(addr2)
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(addr2, provisionalTime))
	// value 3
	_, waitTime, provisionalTime = entries.GetConnectionWaitTime(addr2)
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(addr2, provisionalTime))

	data2, _ = entries.Get(info2.ID, addressDataKey)
	ad2 = data2.(addressData)
	phBookData = ad2.recentConnectionTimes
	// all three times should be queued
	require.Equal(t, 3, len(phBookData))

	// add another element to trigger wait
	_, waitTime, provisionalTime = entries.GetConnectionWaitTime(addr2)
	require.Greater(t, int64(waitTime), int64(0))
	// no element should be removed
	data2, _ = entries.Get(info2.ID, addressDataKey)
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
	_, waitTime, provisionalTime = entries.GetConnectionWaitTime(addr2)
	require.Equal(t, time.Duration(0), waitTime)
	require.Equal(t, true, entries.UpdateConnectionTime(addr2, provisionalTime))
	// only one element should be removed, and one added
	data2, _ = entries.Get(info2.ID, addressDataKey)
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

	ph, err := MakePhonebook(1, 1)
	require.NoError(t, err)
	ph.ReplacePeerList(relaysSet, "default", PhoneBookEntryRelayRole)
	ph.ReplacePeerList(archiverSet, "default", PhoneBookEntryArchiverRole)
	require.Equal(t, len(relaysSet)+len(archiverSet), len(ph.Peers()))
	require.Equal(t, len(relaysSet)+len(archiverSet), ph.Length())

	for _, role := range []PhoneBookEntryRoles{PhoneBookEntryRelayRole, PhoneBookEntryArchiverRole} {
		for k := 0; k < 100; k++ {
			for l := 0; l < 3; l++ {
				entries := ph.GetAddresses(l, role)
				if role == PhoneBookEntryRelayRole {
					for _, entry := range entries {
						require.Contains(t, entry, "relay")
					}
				} else if role == PhoneBookEntryArchiverRole {
					for _, entry := range entries {
						require.Contains(t, entry, "archiver")
					}
				}
			}
		}
	}
}
