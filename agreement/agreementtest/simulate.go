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

// Package agreementtest produces useful functions for testing code.
package agreementtest

import (
	"fmt"
	"strconv"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/agreement/gossip"
	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/timers"
)

type instant struct {
	Z0, Z1          chan struct{}
	timeoutAtCalled chan struct{}
	eventsQueues    map[string]int
	mu              deadlock.Mutex
}

func makeInstant() *instant {
	i := new(instant)
	i.Z0 = make(chan struct{}, 1)
	i.Z1 = make(chan struct{})
	i.timeoutAtCalled = make(chan struct{})
	i.eventsQueues = make(map[string]int)
	return i
}

func (i *instant) Decode([]byte) (timers.Clock, error) {
	return i, nil
}

func (i *instant) Encode() []byte {
	return nil
}

func (i *instant) TimeoutAt(d time.Duration) <-chan time.Time {
	ta := make(chan time.Time)
	select {
	case <-i.timeoutAtCalled:
	default:
		close(i.timeoutAtCalled)
		return ta
	}

	if d == agreement.FilterTimeout(0, protocol.ConsensusCurrentVersion) && !i.HasPending("pseudonode") {
		close(ta)
	}
	return ta
}

func (i *instant) Zero() timers.Clock {
	i.Z0 <- struct{}{}
	// pause here until runRound is called
	i.Z1 <- struct{}{}
	return i
}

func (i *instant) runRound(r basics.Round) {
	<-i.Z1 // wait until Zero is called
	<-i.timeoutAtCalled
	<-i.Z0
}

func (i *instant) shutdown() {
	<-i.Z1
}

func (i *instant) UpdateEventsQueue(queueName string, queueLength int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.eventsQueues[queueName] = queueLength
}

func (i *instant) HasPending(queueName string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	v, has := i.eventsQueues[queueName]

	if !has {
		return false
	}

	if v == 0 {
		return false
	}

	return true
}

type blackhole struct {
	mocks.MockNetwork
}

func (b *blackhole) Address() (string, bool) {
	return "blackhole", true
}

// CryptoRandomSource is a random source that is based off our crypto library.
type CryptoRandomSource struct{}

// Uint64 implements the randomness by calling hte crypto library.
func (c *CryptoRandomSource) Uint64() uint64 {
	return crypto.RandUint64()
}

// Simulate n rounds of agreement on the specified Ledger given the specified
// KeyManager, BlockFactory, and BlockValidator.
//
// If a nonzero roundDeadline is given, this function will return an error if
// any round does not conclude by the deadline.
//
// The KeyManager must have enough keys to form a cert-quorum.
func Simulate(dbname string, n basics.Round, roundDeadline time.Duration, ledger agreement.Ledger, keyManager agreement.KeyManager, proposalFactory agreement.BlockFactory, proposalValidator agreement.BlockValidator, log logging.Logger) error {
	startRound := ledger.NextRound()
	stopRound := startRound + n
	// stop when ledger.NextRound() == stopRound

	accessor, err := db.MakeAccessor(dbname+"_simulate_"+strconv.Itoa(int(stopRound))+"_crash.db", false, true)
	if err != nil {
		return err
	}
	defer accessor.Close()

	stopwatch := makeInstant()
	parameters := agreement.Parameters{
		Logger:         log,
		Accessor:       accessor,
		Clock:          stopwatch,
		Network:        gossip.WrapNetwork(new(blackhole), log),
		Ledger:         ledger,
		BlockFactory:   proposalFactory,
		BlockValidator: proposalValidator,
		KeyManager:     keyManager,
		Local: config.Local{
			CadaverSizeTarget: 200 * 1024,
		},
		RandomSource:            &CryptoRandomSource{},
		EventsProcessingMonitor: stopwatch,
	}
	_ = accessor

	service := agreement.MakeService(parameters)
	service.Start()
	defer service.Shutdown()
	defer stopwatch.shutdown()
	for ledger.NextRound() < stopRound {
		r := ledger.NextRound()
		stopwatch.runRound(r)

		deadlineCh := time.After(roundDeadline)
		if roundDeadline == 0 {
			deadlineCh = nil
		}

		select {
		case <-ledger.Wait(r):
		case <-deadlineCh:
			return fmt.Errorf("agreementtest.Simulate: round %d failed to complete by the deadline (%v)", r, roundDeadline)
		}
	}

	return nil
}
