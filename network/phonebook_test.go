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
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPhonebookAll(t *testing.T, set []string, ph Phonebook) {
	actual := ph.GetAddresses(len(set))
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

func testPhonebookUniform(t *testing.T, set []string, ph Phonebook, getsize int) {
	uniformityTestLength := 250000 / len(set)
	expected := (uniformityTestLength * getsize) / len(set)
	counts := make([]int, len(set))
	for i := 0; i < uniformityTestLength; i++ {
		actual := ph.GetAddresses(getsize)
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

func TestArrayPhonebookAll(t *testing.T) {
	set := []string{"a", "b", "c", "d", "e"}
	ph := MakeArrayPhonebook(1, 1)
	for _, e := range set {
		ph.Entries.data[e] = phonebookData{}
	}
	testPhonebookAll(t, set, ph)
}

func TestArrayPhonebookUniform1(t *testing.T) {
	set := []string{"a", "b", "c", "d", "e"}
	ph := MakeArrayPhonebook(1, 1)
	for _, e := range set {
		ph.Entries.data[e] = phonebookData{}
	}
	testPhonebookUniform(t, set, ph, 1)
}

func TestArrayPhonebookUniform3(t *testing.T) {
	set := []string{"a", "b", "c", "d", "e"}
	ph := MakeArrayPhonebook(1, 1)
	for _, e := range set {
		ph.Entries.data[e] = phonebookData{}
	}
	testPhonebookUniform(t, set, ph, 3)
}

func extenderThread(th *ThreadsafePhonebook, more []string, wg *sync.WaitGroup, repetitions int) {
	defer wg.Done()
	for i := 0; i <= repetitions; i++ {
		start := rand.Intn(len(more))
		end := rand.Intn(len(more)-start) + start
		th.ExtendPeerList(more[start:end])
	}
	th.ExtendPeerList(more)
}

func TestThreadsafePhonebookExtension(t *testing.T) {
	set := []string{"a", "b", "c", "d", "e"}
	more := []string{"f", "g", "h", "i", "j"}
	ph := MakeThreadsafePhonebook(1, 1)
	ph.ReplacePeerList(set)
	wg := sync.WaitGroup{}
	wg.Add(5)
	for ti := 0; ti < 5; ti++ {
		go extenderThread(ph, more, &wg, 1000)
	}
	wg.Wait()

	assert.Equal(t, 10, ph.Length())
}

func threadTestThreadsafePhonebookExtensionLong(wg *sync.WaitGroup, ph *ThreadsafePhonebook, setSize, repetitions int) {
	set := make([]string, setSize)
	for i := range set {
		set[i] = fmt.Sprintf("%06d", i)
	}
	rand.Shuffle(len(set), func(i, j int) { t := set[i]; set[i] = set[j]; set[j] = t })
	extenderThread(ph, set, wg, repetitions)
}

func TestThreadsafePhonebookExtensionLong(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
		return
	}
	ph := MakeThreadsafePhonebook(1, 1)
	wg := sync.WaitGroup{}
	const threads = 5
	const setSize = 1000
	const repetitions = 100
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go threadTestThreadsafePhonebookExtensionLong(&wg, ph, setSize, repetitions)
	}

	wg.Wait()

	assert.Equal(t, setSize, ph.Length())
}

func TestMultiPhonebook(t *testing.T) {
	set := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	pha := MakeArrayPhonebook(1, 1)
	for _, e := range set[:5] {
		pha.Entries.data[e] = phonebookData{}
	}
	phb := MakeArrayPhonebook(1, 1)
	for _, e := range set[5:] {
		phb.Entries.data[e] = phonebookData{}
	}
	mp := MakeMultiPhonebook()
	mp.AddOrUpdatePhonebook("pha", pha)
	mp.AddOrUpdatePhonebook("phb", phb)

	testPhonebookAll(t, set, mp)
	testPhonebookUniform(t, set, mp, 1)
	testPhonebookUniform(t, set, mp, 3)
}

func TestMultiPhonebookDuplicateFiltering(t *testing.T) {
	set := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	pha := MakeArrayPhonebook(1, 1)
	for _, e := range set[:7] {
		pha.Entries.data[e] = phonebookData{}
	}
	phb := MakeArrayPhonebook(1, 1)
	for _, e := range set[3:] {
		phb.Entries.data[e] = phonebookData{}
	}
	mp := MakeMultiPhonebook()
	mp.AddOrUpdatePhonebook("pha", pha)
	mp.AddOrUpdatePhonebook("phb", phb)

	testPhonebookAll(t, set, mp)
	testPhonebookUniform(t, set, mp, 1)
	testPhonebookUniform(t, set, mp, 3)
}

func TestWaitAndAddConnectionTimeLongtWindow(t *testing.T) {
	entries := makePhonebookEntries(3, 200*time.Millisecond)
	addr1 := "addrABC"
	addr2 := "addrXYZ"

	// Address not in. Should return false
	addrInPhonebook, _, provisionalTime := entries.waitForConnectionTime(addr1)
	require.Equal(t, false, addrInPhonebook)
	require.Equal(t, false, entries.updateConnectionTime(addr1, provisionalTime))

	// Test the addresses are populated in the phonebook and a
	// time can be added to one of them
	entries.ReplacePeerList([]string{addr1, addr2})
	_, waited, provisionalTime := entries.waitForConnectionTime(addr1)
	require.Equal(t, false, waited)
	require.Equal(t, true, entries.updateConnectionTime(addr1, provisionalTime))
	phBookData := entries.data[addr1].recentConnectionTimes
	require.Equal(t, 1, len(phBookData))

	// introduce a gap between the two requests
	time.Sleep(100 * time.Millisecond)

	// add another value to addr
	_, waited, provisionalTime = entries.waitForConnectionTime(addr1)
	require.Equal(t, false, waited)
	require.Equal(t, true, entries.updateConnectionTime(addr1, provisionalTime))
	phBookData = entries.data[addr1].recentConnectionTimes
	require.Equal(t, 2, len(phBookData))

	// wait for the time the first element should be removed
	time.Sleep(100 * time.Millisecond)

	// the first time should be removed and a new one added
	// there should not be any wait
	_, waited, provisionalTime = entries.waitForConnectionTime(addr1)
	require.Equal(t, false, waited)
	require.Equal(t, true, entries.updateConnectionTime(addr1, provisionalTime))
	phBookData2 := entries.data[addr1].recentConnectionTimes
	require.Equal(t, 2, len(phBookData2))

	// make sure the right time was removed
	require.Equal(t, phBookData[1], phBookData2[0])
	require.Equal(t, true, phBookData2[0].Before(phBookData2[1]))

	// try requesting from another address, make sure
	// a separate array is used for these new requests

	// add 3 values to another address. should not wait
	// value 1
	_, waited, provisionalTime = entries.waitForConnectionTime(addr2)
	require.Equal(t, false, waited)
	require.Equal(t, true, entries.updateConnectionTime(addr2, provisionalTime))
	// value 2
	_, waited, provisionalTime = entries.waitForConnectionTime(addr2)
	require.Equal(t, false, waited)
	require.Equal(t, true, entries.updateConnectionTime(addr2, provisionalTime))
	// value 3
	_, waited, provisionalTime = entries.waitForConnectionTime(addr2)
	require.Equal(t, false, waited)
	require.Equal(t, true, entries.updateConnectionTime(addr2, provisionalTime))

	phBookData = entries.data[addr2].recentConnectionTimes
	// all three times should be queued
	require.Equal(t, 3, len(phBookData))

	// add another element to trigger wait
	_, waited, provisionalTime = entries.waitForConnectionTime(addr2)
	require.Equal(t, true, waited)
	require.Equal(t, true, entries.updateConnectionTime(addr2, provisionalTime))
	// only one element should be removed, and one added
	phBookData2 = entries.data[addr2].recentConnectionTimes
	require.Equal(t, 3, len(phBookData))

	// make sure the right time was removed
	require.Equal(t, phBookData[1], phBookData2[0])
	require.Equal(t, phBookData[2], phBookData2[1])
}

func TestWaitAndAddConnectionTimeShortWindow(t *testing.T) {
	entries := makePhonebookEntries(3, 2*time.Millisecond)
	addr1 := "addrABC"

	// Init the data structures
	entries.ReplacePeerList([]string{addr1})

	// add 3 values. should not wait
	// value 1
	addrInPhonebook, waited, provisionalTime := entries.waitForConnectionTime(addr1)
	require.Equal(t, true, addrInPhonebook)
	require.Equal(t, false, waited)
	require.Equal(t, true, entries.updateConnectionTime(addr1, provisionalTime))
	// value 2
	_, waited, provisionalTime = entries.waitForConnectionTime(addr1)
	require.Equal(t, false, waited)
	require.Equal(t, true, entries.updateConnectionTime(addr1, provisionalTime))
	// value 3
	_, waited, provisionalTime = entries.waitForConnectionTime(addr1)
	require.Equal(t, false, waited)
	require.Equal(t, true, entries.updateConnectionTime(addr1, provisionalTime))

	// give enough time to expire all the elements
	time.Sleep(10 * time.Millisecond)

	// there should not be any wait
	_, waited, provisionalTime = entries.waitForConnectionTime(addr1)
	require.Equal(t, false, waited)
	require.Equal(t, true, entries.updateConnectionTime(addr1, provisionalTime))

	// only one time should be left (the newly added)
	phBookData := entries.data[addr1].recentConnectionTimes
	require.Equal(t, 1, len(phBookData))
}

func BenchmarkThreadsafePhonebook(b *testing.B) {
	ph := MakeThreadsafePhonebook(1, 1)
	threads := 5
	if b.N < threads {
		threads = b.N
	}
	wg := sync.WaitGroup{}
	wg.Add(threads)
	repetitions := b.N / threads
	for t := 0; t < threads; t++ {
		go threadTestThreadsafePhonebookExtensionLong(&wg, ph, 1000, repetitions)
	}
	wg.Wait()
}
