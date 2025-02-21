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

package phonebook

import (
	"math"
	"math/rand"
	"slices"
	"time"

	"github.com/algorand/go-deadlock"
)

// getAllAddresses when using GetAddresses with getAllAddresses, all the addresses will be retrieved, regardless
// of how many addresses the phonebook actually has. ( with the retry-after logic applied )
const getAllAddresses = math.MaxInt32

// RoleSet defines the roles that a single entry on the phonebook can take.
// currently, we have two roles : relay role and archival role, which are mutually exclusive.
//
//msgp:ignore Roles
type RoleSet struct {
	roles Role
	_     func() // func is not comparable so that Roles. This is to prevent roles misuse and direct comparison.
}

// Role is a single role that a phonebook entry can have.
type Role uint8

const (
	// RelayRole used for all the relays that are provided either via the algobootstrap SRV record
	// or via a configuration file.
	RelayRole Role = 1 << iota
	// ArchivalRole used for all the archival nodes that are provided via the archive SRV record.
	ArchivalRole
)

// Has checks if the role in this role set has the other role
func (r RoleSet) Has(other Role) bool {
	return r.roles&other != 0
}

// Is checks if this set of roles is exactly the same as the other roles
func (r RoleSet) Is(other Role) bool {
	return r.roles == other
}

// Add adds the other roles to this set of roles
func (r *RoleSet) Add(other Role) {
	r.roles |= other
}

// Remove removes the other role from this set of roles
func (r *RoleSet) Remove(other Role) {
	r.roles &= ^other
}

// MakeRoleSet creates a new RoleSet with the passed role
func MakeRoleSet(role Role) RoleSet {
	return RoleSet{roles: role}
}

// Phonebook stores or looks up addresses of nodes we might contact
type Phonebook interface {
	// GetAddresses(N) returns up to N addresses, but may return fewer
	GetAddresses(n int, role Role) []string

	// UpdateRetryAfter updates the retry-after field for the entries matching the given address
	UpdateRetryAfter(addr string, retryAfter time.Time)

	// GetConnectionWaitTime will calculate and return the wait
	// time to prevent exceeding connectionsRateLimitingCount.
	// The connection should be established when the waitTime is 0.
	// It will register a provisional next connection time when the waitTime is 0.
	// The provisional time should be updated after the connection with UpdateConnectionTime
	GetConnectionWaitTime(addrOrPeerID string) (addrInPhonebook bool,
		waitTime time.Duration, provisionalTime time.Time)

	// UpdateConnectionTime will update the provisional connection time.
	// Returns true of the addr was in the phonebook
	UpdateConnectionTime(addrOrPeerID string, provisionalTime time.Time) bool

	// ReplacePeerList merges a set of addresses with that passed in for networkName
	// new entries in dnsAddresses are being added
	// existing items that aren't included in dnsAddresses are being removed
	// matching entries roles gets updated as needed and persistent peers are not touched
	ReplacePeerList(dnsAddresses []string, networkName string, role Role)

	// AddPersistentPeers stores addresses of peers which are persistent.
	// i.e. they won't be replaced by ReplacePeerList calls.
	// If a peer is already in the peerstore, its role will be updated.
	AddPersistentPeers(dnsAddresses []string, networkName string, role Role)
}

// addressData: holds the information associated with each phonebook address.
type addressData struct {
	// retryAfter is the time to wait before retrying to connect to the address.
	retryAfter time.Time

	// recentConnectionTimes: is the log of connection times used to observe the maximum
	//                        connections to the address in a given time window.
	recentConnectionTimes []time.Time

	// networkNames: lists the networks to which the given address belongs.
	networkNames map[string]bool

	// roles is the roles that this address serves.
	roles RoleSet

	// persistent is set true for peers whose record should not be removed for the peer list
	persistent bool
}

// makePhonebookEntryData creates a new addressData entry for provided network name and role.
func makePhonebookEntryData(networkName string, role RoleSet, persistent bool) addressData {
	pbData := addressData{
		networkNames:          make(map[string]bool),
		recentConnectionTimes: make([]time.Time, 0),
		roles:                 role,
		persistent:            persistent,
	}
	pbData.networkNames[networkName] = true
	return pbData
}

// phonebookImpl holds the server connection configuration values
// and the list of request times within the time window for each
// address.
type phonebookImpl struct {
	connectionsRateLimitingCount  uint
	connectionsRateLimitingWindow time.Duration
	data                          map[string]addressData
	lock                          deadlock.RWMutex
}

// MakePhonebook creates phonebookImpl with the passed configuration values
func MakePhonebook(connectionsRateLimitingCount uint,
	connectionsRateLimitingWindow time.Duration) Phonebook {
	return &phonebookImpl{
		connectionsRateLimitingCount:  connectionsRateLimitingCount,
		connectionsRateLimitingWindow: connectionsRateLimitingWindow,
		data:                          make(map[string]addressData, 0),
	}
}

func (e *phonebookImpl) deletePhonebookEntry(entryName, networkName string) {
	pbEntry := e.data[entryName]
	delete(pbEntry.networkNames, networkName)
	if len(pbEntry.networkNames) == 0 {
		delete(e.data, entryName)
	}
}

// PopEarliestTime removes the earliest time from recentConnectionTimes in
// addressData for addr
// It is expected to be later than ConnectionsRateLimitingWindow
func (e *phonebookImpl) popNElements(n int, addr string) {
	entry := e.data[addr]
	entry.recentConnectionTimes = entry.recentConnectionTimes[n:]
	e.data[addr] = entry
}

// AppendTime adds the current time to recentConnectionTimes in
// addressData of addr
func (e *phonebookImpl) appendTime(addr string, t time.Time) {
	entry := e.data[addr]
	entry.recentConnectionTimes = append(entry.recentConnectionTimes, t)
	e.data[addr] = entry
}

func (e *phonebookImpl) filterRetryTime(t time.Time, role Role) []string {
	o := make([]string, 0, len(e.data))
	for addr, entry := range e.data {
		if t.After(entry.retryAfter) && entry.roles.Has(role) {
			o = append(o, addr)
		}
	}
	return o
}

// ReplacePeerList merges a set of addresses with that passed in.
// new entries in addressesThey are being added
// existing items that aren't included in addressesThey are being removed
// matching entries roles gets updated as needed and persistent peers are not touched
func (e *phonebookImpl) ReplacePeerList(addressesThey []string, networkName string, role Role) {
	e.lock.Lock()
	defer e.lock.Unlock()

	// prepare a map of items we'd like to remove.
	removeItems := make(map[string]bool, 0)
	for k, pbd := range e.data {
		if pbd.networkNames[networkName] && !pbd.persistent {
			if pbd.roles.Is(role) {
				removeItems[k] = true
			} else if pbd.roles.Has(role) {
				pbd.roles.Remove(role)
				e.data[k] = pbd
			}
		}
	}

	for _, addr := range addressesThey {
		if pbData, has := e.data[addr]; has {
			// we already have this
			if pbData.persistent {
				// do not touch persistent peers
				continue
			}
			// otherwise update the networkName and role
			pbData.networkNames[networkName] = true
			pbData.roles.Add(role)
			e.data[addr] = pbData

			// do not remove this entry
			delete(removeItems, addr)
		} else {
			// we don't have this item. add it.
			e.data[addr] = makePhonebookEntryData(networkName, RoleSet{roles: role}, false)
		}
	}

	// remove items that were missing in addressesThey
	for k := range removeItems {
		e.deletePhonebookEntry(k, networkName)
	}
}

// AddPersistentPeers stores addresses of peers which are persistent.
// i.e. they won't be replaced by ReplacePeerList calls.
// If a peer is already in the peerstore, its role will be updated.
func (e *phonebookImpl) AddPersistentPeers(dnsAddresses []string, networkName string, role Role) {
	e.lock.Lock()
	defer e.lock.Unlock()

	for _, addr := range dnsAddresses {
		if pbData, has := e.data[addr]; has {
			// we already have this.
			// Make sure the persistence field is set to true and overwrite the role
			pbData.persistent = true
			pbData.roles = MakeRoleSet(role)
			e.data[addr] = pbData
		} else {
			// we don't have this item. add it.
			e.data[addr] = makePhonebookEntryData(networkName, RoleSet{roles: role}, true)
		}
	}
}

func (e *phonebookImpl) UpdateRetryAfter(addr string, retryAfter time.Time) {
	e.lock.Lock()
	defer e.lock.Unlock()

	var entry addressData

	entry, found := e.data[addr]
	if !found {
		return
	}
	entry.retryAfter = retryAfter
	e.data[addr] = entry
}

// GetConnectionWaitTime will calculate and return the wait
// time to prevent exceeding connectionsRateLimitingCount.
// The connection should be established when the waitTime is 0.
// It will register a provisional next connection time when the waitTime is 0.
// The provisional time should be updated after the connection with UpdateConnectionTime
func (e *phonebookImpl) GetConnectionWaitTime(addrOrPeerID string) (addrInPhonebook bool,
	waitTime time.Duration, provisionalTime time.Time) {

	addr := addrOrPeerID
	e.lock.Lock()
	defer e.lock.Unlock()

	_, addrInPhonebook = e.data[addr]
	curTime := time.Now()
	if !addrInPhonebook {
		// The addr is not in this phonebook.
		// Will find the addr in a different phonebook.
		return addrInPhonebook, 0 /* not used */, curTime /* not used */
	}

	var timeSince time.Duration
	var numElmtsToRemove int
	// Remove from recentConnectionTimes the times later than ConnectionsRateLimitingWindowSeconds
	for numElmtsToRemove < len(e.data[addr].recentConnectionTimes) {
		timeSince = curTime.Sub((e.data[addr].recentConnectionTimes)[numElmtsToRemove])
		if timeSince >= e.connectionsRateLimitingWindow {
			numElmtsToRemove++
		} else {
			break // break the loop. The rest are earlier than 1 second
		}
	}
	// Remove the expired elements from e.data[addr].recentConnectionTimes
	e.popNElements(numElmtsToRemove, addr)

	// If there are max number of connections within the time window, wait
	numElts := len(e.data[addr].recentConnectionTimes)
	if uint(numElts) >= e.connectionsRateLimitingCount {
		return addrInPhonebook, /* true */
			(e.connectionsRateLimitingWindow - timeSince), curTime /* not used */
	}

	// Else, there is space in connectionsRateLimitingCount. The
	// connection request of the caller will proceed
	// Update curTime, since it may have significantly changed if waited
	provisionalTime = time.Now()
	// Append the provisional time for the next connection request
	e.appendTime(addr, provisionalTime)
	return addrInPhonebook /* true */, 0 /* no wait. proceed */, provisionalTime
}

// UpdateConnectionTime will update the provisional connection time.
// Returns true of the addr was in the phonebook
func (e *phonebookImpl) UpdateConnectionTime(addrOrPeerID string, provisionalTime time.Time) bool {
	addr := addrOrPeerID
	e.lock.Lock()
	defer e.lock.Unlock()

	entry, found := e.data[addr]
	if !found {
		return false
	}

	defer func() {
		e.data[addr] = entry
	}()

	// Find the provisionalTime and update it
	for indx, val := range entry.recentConnectionTimes {
		if provisionalTime == val {
			entry.recentConnectionTimes[indx] = time.Now()
			return true
		}
	}
	// Case where the time is not found: it was removed from the list.
	// This may happen when the time expires before the connection was established with the server.
	// The time should be added again.
	entry.recentConnectionTimes = append(entry.recentConnectionTimes, time.Now())
	return true
}

func shuffleStrings(set []string) {
	rand.Shuffle(len(set), func(i, j int) { t := set[i]; set[i] = set[j]; set[j] = t })
}

func shuffleSelect(set []string, n int) []string {
	if n >= len(set) || n == getAllAddresses {
		// return shuffled copy of everything
		out := slices.Clone(set)
		shuffleStrings(out)
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
	out := make([]string, n)
	for i, index := range indexSample {
		out[i] = set[index]
	}
	return out
}

// GetAddresses returns up to N shuffled address
func (e *phonebookImpl) GetAddresses(n int, role Role) []string {
	e.lock.RLock()
	defer e.lock.RUnlock()
	return shuffleSelect(e.filterRetryTime(time.Now(), role), n)
}

// Length returns the number of addrs contained
func (e *phonebookImpl) Length() int {
	e.lock.RLock()
	defer e.lock.RUnlock()
	return len(e.data)
}
