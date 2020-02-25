// Copyright (C) 2019-2020 Algorand, Inc.
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

package network

import (
	"math"
	"math/rand"
	"time"

	"github.com/algorand/go-deadlock"
)

// when using GetAddresses with getAllAddresses, all the addresses will be retrieved, regardless
// of how many addresses the phonebook actually has. ( with the retry-after logic applied )
const getAllAddresses = math.MaxInt32

const defaultList = "default"

// Phonebook stores or looks up addresses of nodes we might contact
type Phonebook interface {
	// GetAddresses(N) returns up to N addresses, but may return fewer
	GetAddresses(n int) []string

	// UpdateRetryAfter updates the retry-after field for the entries matching the given address
	UpdateRetryAfter(addr string, retryAfter time.Time)

	// GetConnectionWaitTime will calculate and return the wait
	// time to prevent exceeding connectionsRateLimitingCount.
	// The connection should be established when the waitTime is 0.
	// It will register a provisional next connection time when the waitTime is 0.
	// The provisional time should be updated after the connection with UpdateConnectionTime
	GetConnectionWaitTime(addr string) (addrInPhonebook bool,
		waitTime time.Duration, provisionalTime time.Time)

	// UpdateConnectionTime will update the provisional connection time.
	// Returns true of the addr was in the phonebook
	UpdateConnectionTime(addr string, provisionalTime time.Time) bool
}

type phonebookData struct {
	retryAfter            time.Time
	recentConnectionTimes []time.Time
	phonebookName          map[string]bool
}

func makePhonebookData(phonebookName string) phonebookData {
	pbData := phonebookData{
		phonebookName: make(map[string] bool),
		retryAfter: 0,
		recentConnectionTimes: make([]time.Time, 0)
	}
	pbData.phonebookName[phonebookName] = true
	return pbData
}

// phonebookEntries holds the server connection configuration values
// and the list of request times withing the time window for each
// address.
type phonebookEntries struct {
	connectionsRateLimitingCount  uint
	connectionsRateLimitingWindow time.Duration
	data                          map[string]phonebookData
	lock    deadlock.RWMutex	
}

// makePhonebookEntries creates phonebookEntries with the passed configuration values
func makePhonebookEntries(connectionsRateLimitingCount uint,
	connectionsRateLimitingWindow time.Duration) phonebookEntries {
	return phonebookEntries{
		connectionsRateLimitingCount:  connectionsRateLimitingCount,
		connectionsRateLimitingWindow: connectionsRateLimitingWindow,
		data:                          make(map[string]phonebookData, 0),
	}
}

func (e *phonebookEntries) deletePhonebookEntry(entryName, phonebookName string) {
	e.lock.Lock()
	defer p.lock.Unlock()

	pbEntry := e.data[entryName]
	delete(pbEntry.phonebookNames, phonebookName)
	if 0 == len(phbEntry.phoneboobNames) {
		delete(e.data, entryName)
	}
}

// PopEarliestTime removes the earliest time from recentConnectionTimes in
// phonebookData for addr
// It is expected to be later than ConnectionsRateLimitingWindow
func (e *phonebookEntries) popNElements(n int, addr string) {
	e.lock.Lock()
	defer p.lock.Unlock()

	entry := e.data[addr]
	entry.recentConnectionTimes = entry.recentConnectionTimes[n:]
	e.data[addr] = entry
}

// AppendTime adds the current time to recentConnectionTimes in
// phonebookData of addr
func (e *phonebookEntries) appendTime(addr string, t time.Time) {
	e.lock.Lock()
	defer p.lock.Unlock()

	entry := e.data[addr]
	entry.recentConnectionTimes = append(entry.recentConnectionTimes, t)
	e.data[addr] = entry
}

func (e *phonebookEntries) filterRetryTime(t time.Time) []string {
	e.lock.RLock()
	defer p.lock.RUnlock()

	o := make([]string, 0, len(e.data))
	for addr, entry := range e.data {
		if t.After(entry.retryAfter) {
			o = append(o, addr)
		}
	}
	return o
}

// ReplacePeerList merges a set of addresses with that passed in.
// new entries in they are being added
// existing items that aren't included in they are being removed
// matching entries don't change
func (e *phonebookEntries) ReplacePeerList(they []string) {	
	e.ReplacePeerList(they, defaultList)
}

// ReplacePeerList merges a set of addresses with that passed in.
// new entries in they are being added
// existing items that aren't included in they are being removed
// matching entries don't change
func (e *phonebookEntries) ReplacePeerList(they []string, phonebookName string) {
	e.lock.Lock()
	defer e.lock.Unlock()

	// prepare a map of items we'd like to remove.
	removeItems := make(map[string]bool, 0)
	for k := range e.data {
		removeItems[k] = true
	}

	for _, addr := range they {
		if pbData, has := e.data[addr]; has {
			// we already have this.
			// Update the phonebookName
			pbData.phonebookName[phonebookName] = true

			// do nor remove this entry
			delete(removeItems, addr)
		} else {
			// we don't have this item. add it.
			e.data[addr] = makePhonebookData(phonebookName)
		}
	}

	// remove items that were missing in they
	for k := range removeItems {
		e.deletePhonebookEntry(k, phonebookName)
	}
}

func (e *phonebookEntries) UpdateRetryAfter(addr string, retryAfter time.Time) {
	e.lock.Lock()
	defer e.lock.Unlock()

	var entry phonebookData

	_, found := e.data[addr]
	if !found {
		entry = makePhonebookData(defaultList)
	} else {
		entry := e.data[addr]
	}
	entry.retryAfter = retryAfter
	e.data[addr] = entry
}

// getConnectionWaitTime will calculate and return the wait
// time to prevent exceeding connectionsRateLimitingCount.
// The connection should be established when the waitTime is 0.
// It will register a provisional next connection time when the waitTime is 0.
// The provisional time should be updated after the connection with UpdateConnectionTime
func (e *phonebookEntries) GetConnectionWaitTime(addr string) (addrInPhonebook bool,
	waitTime time.Duration, provisionalTime time.Time) {
	e.lock.Lock()
	defer e.lock.Unlock()

	_, addrInPhonebook = e.data[addr]
	curTime := time.Now()
	if !addrInPhonebook {
		// The addr is not in this phonebook.
		// Will find the addr in a different phonebook.
		return addrInPhonebook, 0 /* not unsed */, curTime /* not unsed */
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
			(e.connectionsRateLimitingWindow - timeSince), curTime /* not unsed */
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
func (e *phonebookEntries) UpdateConnectionTime(addr string, provisionalTime time.Time) bool {
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
		out := make([]string, len(set))
		copy(out, set)
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
func (e *phonebookEntries) GetAddresses(n int) []string {
	e.lock.RLock()
	defer e.lock.RUnlock()
	return shuffleSelect(e.filterRetryTime(time.Now()), n)
}

// ExtendPeerList adds unique addresses to this set of addresses
func (e *phonebookEntries) ExtendPeerList(more []string, phonebookName string) {
	e.lock.Lock()
	defer e.lock.Unlock()
	for _, addr := range more {
		if _, has := e.data[addr]; has {
			continue
		}
		e.data[addr] = makePhonebookData(phonebookName)
	}
}

// Length returns the number of addrs contained
func (e *phonebookEntries) Length() int {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return len(e.data)
}

// GetPhonebook retrieves a phonebook by it's name
func (mp *MultiPhonebook) GetPhonebook(bootstrapNetworkName string) (p Phonebook) {
	mp.lock.Lock()
	defer mp.lock.Unlock()
	return mp.phonebookMap[bootstrapNetworkName]
}

// AddOrUpdatePhonebook adds or updates Phonebook in Phonebook map
func (mp *MultiPhonebook) AddOrUpdatePhonebook(bootstrapNetworkName string, p Phonebook) {
	mp.lock.Lock()
	defer mp.lock.Unlock()
	mp.phonebookMap[bootstrapNetworkName] = p
}

