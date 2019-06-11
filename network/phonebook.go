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
	"math/rand"

	"github.com/algorand/go-deadlock"
)

// Phonebook stores or looks up addresses of nodes we might contact
type Phonebook interface {
	// GetAddresses(N) returns up to N addresses, but may return fewer
	GetAddresses(n int) []string
}

// ArrayPhonebook is a simple wrapper on a slice of string with addresses
type ArrayPhonebook struct {
	Entries []string
}

func shuffleStrings(set []string) {
	rand.Shuffle(len(set), func(i, j int) { t := set[i]; set[i] = set[j]; set[j] = t })
}

func shuffleSelect(set []string, n int) []string {
	if n >= len(set) {
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
func (p *ArrayPhonebook) GetAddresses(n int) []string {
	return shuffleSelect(p.Entries, n)
}

// ThreadsafePhonebook implements Phonebook interface
type ThreadsafePhonebook struct {
	lock  deadlock.RWMutex
	addrs []string
}

// GetAddresses returns up to N shuffled address
func (p *ThreadsafePhonebook) GetAddresses(n int) []string {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return shuffleSelect(p.addrs, n)
}

// ExtendPeerList adds unique addresses to this set of addresses
func (p *ThreadsafePhonebook) ExtendPeerList(more []string) {
	p.lock.Lock()
	defer p.lock.Unlock()
	// TODO: if this gets bad because p.addrs gets long, replace storage with a map[string]bool
	for _, addr := range more {
		found := false
		for _, oaddr := range p.addrs {
			if addr == oaddr {
				found = true
				break
			}
		}
		if !found {
			p.addrs = append(p.addrs, addr)
		}
	}
}

// Length returns the number of addrs contained
func (p *ThreadsafePhonebook) Length() int {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return len(p.addrs)
}

// ReplacePeerList replaces set of addresses with that passed in.
func (p *ThreadsafePhonebook) ReplacePeerList(they []string) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.addrs = make([]string, len(they))
	copy(p.addrs, they)
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
		switch xp := p.(type) {
		case *ArrayPhonebook:
			sizes[pi] = len(xp.Entries)
		case *ThreadsafePhonebook:
			sizes[pi] = xp.Length()
		default:
			addrs[pi] = xp.GetAddresses(1000)
			sizes[pi] = len(addrs[pi])
		}
		total += sizes[pi]
	}
	all := make([]string, total)
	pos := 0
	for pi, size := range sizes {
		if addrs[pi] != nil {
			copy(all[pos:], addrs[pi])
			pos += len(addrs[pi])
		} else {
			xa := mp.phonebooks[pi].GetAddresses(size)
			copy(all[pos:], xa)
			pos += len(xa)
		}
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
