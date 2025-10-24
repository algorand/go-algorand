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
	"fmt"
	"math"
	"math/rand"
	"slices"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	libp2p "github.com/libp2p/go-libp2p/core/peerstore"
	mempstore "github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"

	"github.com/algorand/go-algorand/network/phonebook"
	"github.com/algorand/go-deadlock"
)

// when using GetAddresses with getAllAddresses, all the addresses will be retrieved, regardless
// of how many addresses the phonebook actually has. ( with the retry-after logic applied )
const getAllAddresses = math.MaxInt32

const psmdkAddressData string = "addressData"

// PeerStore implements Peerstore and CertifiedAddrBook.
type PeerStore struct {
	peerStoreCAB
	connectionsRateLimitingCount  uint
	connectionsRateLimitingWindow time.Duration
	lock                          deadlock.Mutex
}

// addressData: holds the information associated with each phonebook address.
type addressData struct {
	// retryAfter is the time to wait before retrying to connect to the address.
	retryAfter time.Time

	// recentConnectionTimes is the log of connection times used to observe the maximum
	// connections to the address in a given time window.
	recentConnectionTimes []time.Time

	// networkNames: lists the networks to which the given address belongs.
	networkNames map[string]bool

	// roles is the roles that this address serves.
	roles phonebook.RoleSet
}

// peerStoreCAB combines the libp2p Peerstore and CertifiedAddrBook interfaces.
type peerStoreCAB interface {
	libp2p.Peerstore
	libp2p.CertifiedAddrBook
}

// NewPeerStore creates a new peerstore backed by a datastore.
func NewPeerStore(addrInfo []*peer.AddrInfo, network string) (*PeerStore, error) {
	ps, err := mempstore.NewPeerstore()
	if err != nil {
		return nil, fmt.Errorf("cannot initialize a peerstore: %w", err)
	}

	pstore := &PeerStore{peerStoreCAB: ps}
	pstore.AddPersistentPeers(addrInfo, network, phonebook.RelayRole)
	return pstore, nil
}

// MakePhonebook creates a phonebook with the passed configuration values
func MakePhonebook(connectionsRateLimitingCount uint,
	connectionsRateLimitingWindow time.Duration) (*PeerStore, error) {
	ps, err := mempstore.NewPeerstore()
	if err != nil {
		return &PeerStore{}, fmt.Errorf("cannot initialize a peerstore: %w", err)
	}
	pstore := &PeerStore{peerStoreCAB: ps,
		connectionsRateLimitingCount:  connectionsRateLimitingCount,
		connectionsRateLimitingWindow: connectionsRateLimitingWindow,
	}
	return pstore, nil
}

// GetAddresses returns up to N addresses, but may return fewer
func (ps *PeerStore) GetAddresses(n int, role phonebook.Role) []*peer.AddrInfo {
	return shuffleSelect(ps.filterRetryTime(time.Now(), role), n)
}

// UpdateRetryAfter updates the retryAfter time for the given address.
func (ps *PeerStore) UpdateRetryAfter(addr string, retryAfter time.Time) {
	info, err := peerInfoFromDomainPort(addr)
	if err != nil {
		return
	}
	metadata, _ := ps.Get(info.ID, psmdkAddressData)
	if metadata != nil {
		ad, ok := metadata.(addressData)
		if !ok {
			return
		}
		ad.retryAfter = retryAfter
		_ = ps.Put(info.ID, psmdkAddressData, ad)
	}

}

// GetConnectionWaitTime will calculate and return the wait
// time to prevent exceeding connectionsRateLimitingCount.
// The connection should be established when the waitTime is 0.
// It will register a provisional next connection time when the waitTime is 0.
// The provisional time should be updated after the connection with UpdateConnectionTime
func (ps *PeerStore) GetConnectionWaitTime(addrOrPeerID string) (bool, time.Duration, time.Time) {
	curTime := time.Now()

	ps.lock.Lock()
	defer ps.lock.Unlock()

	peerID := peer.ID(addrOrPeerID)
	metadata, err := ps.Get(peerID, psmdkAddressData)
	if err != nil {
		return false, 0 /* not used */, curTime /* not used */
	}
	ad, ok := metadata.(addressData)
	if !ok {
		return false, 0 /* not used */, curTime /* not used */
	}

	// Remove from recentConnectionTimes the times later than ConnectionsRateLimitingWindowSeconds
	numElmtsToRemove := 0
	timeSince := time.Duration(0)
	for numElmtsToRemove < len(ad.recentConnectionTimes) {
		timeSince = curTime.Sub(ad.recentConnectionTimes[numElmtsToRemove])
		if timeSince >= ps.connectionsRateLimitingWindow {
			numElmtsToRemove++
		} else {
			break // break the loop. The rest are earlier than 1 second
		}
	}

	// Remove the expired elements from e.data[addr].recentConnectionTimes
	ps.popNElements(numElmtsToRemove, peerID)

	// If there are max number of connections within the time window, wait
	metadata, _ = ps.Get(peerID, psmdkAddressData)
	ad, ok = metadata.(addressData)
	if !ok {
		return false, 0 /* not used */, curTime /* not used */
	}
	numElts := len(ad.recentConnectionTimes)
	if uint(numElts) >= ps.connectionsRateLimitingCount {
		return true, /* true */
			ps.connectionsRateLimitingWindow - timeSince, curTime /* not used */
	}
	// Else, there is space in connectionsRateLimitingCount. The
	// connection request of the caller will proceed
	// Update curTime, since it may have significantly changed if waited
	provisionalTime := time.Now()
	// Append the provisional time for the next connection request
	ps.appendTime(peerID, provisionalTime)
	return true, 0 /* no wait. proceed */, provisionalTime
}

// UpdateConnectionTime updates the connection time for the given address.
func (ps *PeerStore) UpdateConnectionTime(addrOrPeerID string, provisionalTime time.Time) bool {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	peerID := peer.ID(addrOrPeerID)
	metadata, err := ps.Get(peerID, psmdkAddressData)
	if err != nil {
		return false
	}
	ad, ok := metadata.(addressData)
	if !ok {
		return false
	}
	defer func() {
		_ = ps.Put(peerID, psmdkAddressData, ad)

	}()

	// Find the provisionalTime and update it
	entry := ad.recentConnectionTimes
	for indx, val := range entry {
		if provisionalTime.Equal(val) {
			entry[indx] = time.Now()
			return true
		}
	}

	// Case where the time is not found: it was removed from the list.
	// This may happen when the time expires before the connection was established with the server.
	// The time should be added again.
	entry = append(entry, time.Now())
	ad.recentConnectionTimes = entry

	return true
}

// ReplacePeerList replaces the peer list for the given networkName and role.
// new entries in addressesThey are being added
// existing items that aren't included in addressesThey are being removed
// matching entries roles gets updated as needed and persistent peers are not touched
func (ps *PeerStore) ReplacePeerList(addressesThey []*peer.AddrInfo, networkName string, role phonebook.Role) {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	// prepare a map of items we'd like to remove.
	removeItems := make(map[peer.ID]bool, 0)
	peerIDs := ps.Peers()
	for _, pid := range peerIDs {
		data, _ := ps.Get(pid, psmdkAddressData)
		if data != nil {
			ad := data.(addressData)
			updated := false
			if ad.networkNames[networkName] && !ad.roles.IsPersistent(role) {
				if ad.roles.Is(role) {
					removeItems[pid] = true
				} else if ad.roles.Has(role) {
					ad.roles.Remove(role)
					updated = true
				}
			}
			if updated {
				_ = ps.Put(pid, psmdkAddressData, ad)
			}
		}

	}
	for _, info := range addressesThey {
		data, _ := ps.Get(info.ID, psmdkAddressData)
		if data != nil {
			// we already have this
			// update the networkName and role
			ad := data.(addressData)
			ad.networkNames[networkName] = true
			ad.roles.Add(role)
			_ = ps.Put(info.ID, psmdkAddressData, ad)

			// do not remove this entry
			delete(removeItems, info.ID)
		} else {
			// we don't have this item. add it.
			ps.AddAddrs(info.ID, info.Addrs, libp2p.AddressTTL)
			entry := makePhonebookEntryData(networkName, role, false)
			_ = ps.Put(info.ID, psmdkAddressData, entry)
		}
	}

	// remove items that were missing in addressesThey
	for k := range removeItems {
		ps.deletePhonebookEntry(k, networkName)
	}
}

// AddPersistentPeers stores addresses of peers which are persistent.
// i.e. they won't be replaced by ReplacePeerList calls.
// If a peer is already in the peerstore, its role will be updated.
func (ps *PeerStore) AddPersistentPeers(addrInfo []*peer.AddrInfo, networkName string, role phonebook.Role) {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	for _, info := range addrInfo {
		data, _ := ps.Get(info.ID, psmdkAddressData)
		if data != nil {
			// we already have this.
			// Make sure the persistence field is set to true and overwrite the role
			ad := data.(addressData)
			ad.roles.AddPersistent(role)
			_ = ps.Put(info.ID, psmdkAddressData, ad)
		} else {
			// we don't have this item. add it.
			ps.AddAddrs(info.ID, info.Addrs, libp2p.PermanentAddrTTL)
			entry := makePhonebookEntryData(networkName, role, true)
			_ = ps.Put(info.ID, psmdkAddressData, entry)
		}
	}
}

// HasRole checks if the peer has the given role.
func (ps *PeerStore) HasRole(peerID peer.ID, role phonebook.Role) bool {
	data, err := ps.Get(peerID, psmdkAddressData)
	if err != nil || data == nil {
		return false
	}
	ad := data.(addressData)
	return ad.roles.Has(role)
}

// Length returns the number of addrs in peerstore
func (ps *PeerStore) Length() int {
	return len(ps.Peers())
}

// makePhonebookEntryData creates a new address entry for provided network name and role.
func makePhonebookEntryData(networkName string, role phonebook.Role, persistent bool) addressData {
	pbData := addressData{
		networkNames:          make(map[string]bool),
		recentConnectionTimes: make([]time.Time, 0),
		roles:                 phonebook.MakeRoleSet(role, persistent),
	}
	pbData.networkNames[networkName] = true
	return pbData
}

func (ps *PeerStore) deletePhonebookEntry(peerID peer.ID, networkName string) {
	data, err := ps.Get(peerID, psmdkAddressData)
	if err != nil {
		return
	}
	ad := data.(addressData)
	delete(ad.networkNames, networkName)
	isEmpty := len(ad.networkNames) == 0
	if isEmpty {
		ps.ClearAddrs(peerID)
		_ = ps.Put(peerID, psmdkAddressData, nil)
	}
}

// appendTime adds the current time to recentConnectionTimes in
// addressData of addr
func (ps *PeerStore) appendTime(peerID peer.ID, t time.Time) {
	data, _ := ps.Get(peerID, psmdkAddressData)
	ad := data.(addressData)
	ad.recentConnectionTimes = append(ad.recentConnectionTimes, t)
	_ = ps.Put(peerID, psmdkAddressData, ad)
}

// popNElements removes the earliest time from recentConnectionTimes in
// addressData for addr
// It is expected to be later than ConnectionsRateLimitingWindow
func (ps *PeerStore) popNElements(n int, peerID peer.ID) {
	data, _ := ps.Get(peerID, psmdkAddressData)
	ad := data.(addressData)
	ad.recentConnectionTimes = ad.recentConnectionTimes[n:]
	_ = ps.Put(peerID, psmdkAddressData, ad)
}

func (ps *PeerStore) filterRetryTime(t time.Time, role phonebook.Role) []*peer.AddrInfo {
	o := make([]*peer.AddrInfo, 0, len(ps.Peers()))
	for _, peerID := range ps.Peers() {
		data, _ := ps.Get(peerID, psmdkAddressData)
		if data != nil {
			ad := data.(addressData)
			if t.After(ad.retryAfter) && ad.roles.Has(role) {
				mas := ps.Addrs(peerID)
				info := peer.AddrInfo{ID: peerID, Addrs: mas}
				o = append(o, &info)
			}
		}
	}
	return o
}

func shuffleSelect(set []*peer.AddrInfo, n int) []*peer.AddrInfo {
	if n >= len(set) || n == getAllAddresses {
		// return shuffled copy of everything
		out := slices.Clone(set)
		shuffleAddrInfos(out)
		return out
	}
	// Pick random indexes from the set
	indexSample := make([]int, n)
	for i := range indexSample {
		indexSample[i] = rand.Intn(len(set)-i) + i
		for oi, ois := range indexSample[:i] {
			if ois == indexSample[i] {
				indexSample[i] = oi
			}
		}
	}
	out := make([]*peer.AddrInfo, n)
	for i, index := range indexSample {
		out[i] = set[index]
	}
	return out
}

func shuffleAddrInfos(set []*peer.AddrInfo) {
	rand.Shuffle(len(set), func(i, j int) { set[i], set[j] = set[j], set[i] })
}

// RoleChecker is an interface that checks if a peer has a specific role.
type RoleChecker interface {
	HasRole(peerID peer.ID, role phonebook.Role) bool
}
