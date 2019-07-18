// Copyright (C) 2019 Algorand, Inc.
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

// Phonebook stores or looks up addresses of nodes we might contact
type Phonebook interface {
	// GetAddresses(N) returns up to N addresses, but may return fewer
	GetAddresses(n int) []string

	// UpdateRetryAfter updates the retry-after field for the entries matching the given address
	UpdateRetryAfter(addr string, retryAfter time.Time)
}

// phonebookEntry is a single server on the phonebook
/*type phonebookEntry struct {
	address    string
	retryAfter time.Time
}*/

type phonebookData struct {
	retryAfter time.Time
}

type phonebookEntries map[string]phonebookData

// ArrayPhonebook is a simple wrapper on a slice of string with addresses
type ArrayPhonebook struct {
	Entries phonebookEntries
}

// MakeArrayPhonebook creates a ArrayPhonebook
func MakeArrayPhonebook() ArrayPhonebook {
	return ArrayPhonebook{
		Entries: make(phonebookEntries, 0),
	}
}

func (e *phonebookEntries) filterRetryTime(t time.Time) []string {
	o := make([]string, 0, len(*e))
	for addr, entry := range *e {
		if t.After(entry.retryAfter) {
			o = append(o, addr)
		}
	}
	return o
}

// ReplacePeerList replaces set of addresses with that passed in.
func (e *phonebookEntries) ReplacePeerList(they []string) {
	// clear current map.
	for k := range *e {
		delete(*e, k)
	}

	for _, v := range they {
		(*e)[v] = phonebookData{}
	}
}

func (e *phonebookEntries) updateRetryAfter(addr string, retryAfter time.Time) {
	(*e)[addr] = phonebookData{retryAfter: retryAfter}
}

// UpdateRetryAfter updates the retry-after field for the entries matching the given address
func (p ArrayPhonebook) UpdateRetryAfter(addr string, retryAfter time.Time) {
	p.Entries.updateRetryAfter(addr, retryAfter)
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
func (p ArrayPhonebook) GetAddresses(n int) []string {
	return shuffleSelect(p.Entries.filterRetryTime(time.Now()), n)
}

// ThreadsafePhonebook implements Phonebook interface
type ThreadsafePhonebook struct {
	lock    deadlock.RWMutex
	entries phonebookEntries
}

// MakeThreadsafePhonebook creates a ThreadsafePhonebook
func MakeThreadsafePhonebook() ThreadsafePhonebook {
	return ThreadsafePhonebook{
		entries: make(phonebookEntries, 0),
	}
}

// GetAddresses returns up to N shuffled address
func (p *ThreadsafePhonebook) GetAddresses(n int) []string {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return shuffleSelect(p.entries.filterRetryTime(time.Now()), n)
}

// UpdateRetryAfter updates the retry-after field for the entries matching the given address
func (p *ThreadsafePhonebook) UpdateRetryAfter(addr string, retryAfter time.Time) {
	p.lock.RLock()
	defer p.lock.RUnlock()
	p.entries.updateRetryAfter(addr, retryAfter)
}

// ExtendPeerList adds unique addresses to this set of addresses
func (p *ThreadsafePhonebook) ExtendPeerList(more []string) {
	p.lock.Lock()
	defer p.lock.Unlock()
	// TODO: if this gets bad because p.addrs gets long, replace storage with a map[string]bool
	for _, addr := range more {
		if _, has := p.entries[addr]; has {
			continue
		}
		p.entries[addr] = phonebookData{}
	}
}

// Length returns the number of addrs contained
func (p *ThreadsafePhonebook) Length() int {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return len(p.entries)
}

// ReplacePeerList replaces set of addresses with that passed in.
func (p *ThreadsafePhonebook) ReplacePeerList(they []string) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.entries.ReplacePeerList(they)
}

// MergePeerList merges a set of addresses with that passed in.
// new entries in they are being added
// existing items that aren't included in they are being removed
// matching entries don't change
func (p *ThreadsafePhonebook) MergePeerList(they []string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	// prepare a map of items we'd like to remove.
	removeItems := make(map[string]bool, 0)
	for k := range p.entries {
		removeItems[k] = true
	}

	for _, addr := range they {
		if _, has := p.entries[addr]; has {
			// we already have this. do nothing.
			delete(removeItems, addr)
		} else {
			// we don't have this item. add it.
			p.entries[addr] = phonebookData{}
		}
	}

	// remove items that were missing in they
	for k := range removeItems {
		delete(p.entries, k)
	}
}

// MultiPhonebook contains several phonebooks
type MultiPhonebook struct {
	phonebooks []Phonebook
	lock       deadlock.RWMutex
}

// GetAddresses returns up to N address
// TODO: this implementation does a bunch of extra copying, make it more efficient
func (mp *MultiPhonebook) GetAddresses(n int) []string {
	mp.lock.RLock()
	defer mp.lock.RUnlock()
	if len(mp.phonebooks) == 1 {
		return mp.phonebooks[0].GetAddresses(n)
	}
	sizes := make([]int, len(mp.phonebooks))
	total := 0
	addrs := make([][]string, len(mp.phonebooks))
	for pi, p := range mp.phonebooks {
		addrs[pi] = p.GetAddresses(getAllAddresses)
		sizes[pi] = len(addrs[pi])
		total += sizes[pi]
	}
	all := make([]string, total)
	pos := 0
	for pi, sizei := range sizes {
		copy(all[pos:], addrs[pi])
		pos += sizei
	}
	out := all[:pos]
	rand.Shuffle(len(out), func(i, j int) { t := out[i]; out[i] = out[j]; out[j] = t })
	if n < len(out) {
		return out[:n]
	}
	return out
}

// AddPhonebook adds a Phonebook if it is new
func (mp *MultiPhonebook) AddPhonebook(p Phonebook) {
	mp.lock.Lock()
	defer mp.lock.Unlock()
	for _, op := range mp.phonebooks {
		if op == p {
			return
		}
	}
	mp.phonebooks = append(mp.phonebooks, p)
}

// UpdateRetryAfter updates the retry-after field for the entries matching the given address
func (mp *MultiPhonebook) UpdateRetryAfter(addr string, retryAfter time.Time) {
	mp.lock.Lock()
	defer mp.lock.Unlock()
	for _, op := range mp.phonebooks {
		op.UpdateRetryAfter(addr, retryAfter)
	}
}
