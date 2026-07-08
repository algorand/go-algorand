// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package agreement

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/timers"
)

func TestAgreementSerialization(t *testing.T) {
	partitiontest.PartitionTest(t)

	// todo : we need to deserialize some more meaningful state.
	clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	status := player{Round: 350, Step: soft, Deadline: Deadline{Duration: time.Duration(23) * time.Second, Type: TimeoutDeadline}, lowestCredentialArrivals: makeCredentialArrivalHistory(dynamicFilterCredentialArrivalHistory)}
	router := makeRootRouter(status)
	a := []action{checkpointAction{}, disconnectAction(messageEvent{}, nil)}

	encodedBytes := encode(clock, router, status, a)

	t0 := timers.MakeMonotonicClock[TimeoutType](time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC))
	log := makeServiceLogger(logging.Base())
	clock2, router2, status2, a2, err := decode(encodedBytes, t0, log)
	require.NoError(t, err)
	require.Equalf(t, clock, clock2, "Clock wasn't serialized/deserialized correctly")
	require.Equalf(t, router, router2, "Router wasn't serialized/deserialized correctly")
	require.Equalf(t, status, status2, "Status wasn't serialized/deserialized correctly")
	require.Equalf(t, a, a2, "Action wasn't serialized/deserialized correctly")

	// also check if old version gets "upgraded" as side effect of decode
	clock3 := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	status3 := player{Round: 350, Step: soft, OldDeadline: time.Duration(23) * time.Second}
	router3 := makeRootRouter(status3)
	a3 := []action{checkpointAction{}, disconnectAction(messageEvent{}, nil)}

	encodedBytes2 := encode(clock3, router3, status3, a3)

	t1 := timers.MakeMonotonicClock[TimeoutType](time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC))
	clock4, router4, status4, a4, err := decode(encodedBytes2, t1, log)
	require.NoError(t, err)
	require.Equalf(t, clock, clock4, "Clock wasn't serialized/deserialized correctly")
	require.Equalf(t, status, status4, "Status wasn't serialized/deserialized correctly")
	require.Equalf(t, router, router4, "Router wasn't serialized/deserialized correctly")
	require.Equalf(t, a, a4, "Action wasn't serialized/deserialized correctly")
}

func BenchmarkAgreementSerialization(b *testing.B) {
	// todo : we need to deserialize some more meaningful state.
	b.SkipNow()

	clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	status := player{Round: 350, Step: soft, Deadline: Deadline{Duration: time.Duration(23) * time.Second, Type: TimeoutDeadline}}
	router := makeRootRouter(status)
	a := []action{}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		encode(clock, router, status, a)
	}
}

func BenchmarkAgreementDeserialization(b *testing.B) {
	// todo : we need to deserialize some more meaningful state.
	b.SkipNow()

	clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	status := player{Round: 350, Step: soft, Deadline: Deadline{Duration: time.Duration(23) * time.Second, Type: TimeoutDeadline}}
	router := makeRootRouter(status)
	a := []action{}

	encodedBytes := encode(clock, router, status, a)
	t0 := timers.MakeMonotonicClock[TimeoutType](time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC))
	log := makeServiceLogger(logging.Base())
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		decode(encodedBytes, t0, log)
	}
}

func TestAgreementPersistence(t *testing.T) {
	partitiontest.PartitionTest(t)

	accessor, err := db.MakeAccessor(t.Name()+"_crash.db", false, true)
	require.NoError(t, err)
	defer accessor.Close()

	accessor.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return agreeInstallDatabase(tx)
	}) // ignore error

	p := player{
		Round:  370,
		Period: 8,
		Step:   15,
	}

	raw := [100 * 1024]byte{}
	crypto.RandBytes(raw[:])
	persist(serviceLogger{Logger: logging.Base()}, accessor, p.Round, p.Period, p.Step, raw[:])

	raw2, err := restore(serviceLogger{Logger: logging.Base()}, accessor)
	require.NoError(t, err)
	require.Equalf(t, raw[:], raw2[:], "raw data was persisted incorrectly.")
}

func BenchmarkAgreementPersistence(b *testing.B) {

	// temporary skip now until we implement more meaningfull test.
	b.SkipNow()

	accessor, _ := db.MakeAccessor(b.Name()+"_crash.db", false, true)
	defer accessor.Close()

	accessor.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return agreeInstallDatabase(tx)
	}) // ignore error

	p := player{
		Round:  370,
		Period: 8,
		Step:   15,
	}

	raw := [100 * 1024]byte{}
	crypto.RandBytes(raw[:])
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		persist(serviceLogger{Logger: logging.Base()}, accessor, p.Round, p.Period, p.Step, raw[:])
	}
}

func BenchmarkAgreementPersistenceRecovery(b *testing.B) {

	// temporary skip now until we implement more meaningfull test.
	b.SkipNow()

	accessor, _ := db.MakeAccessor(b.Name()+"_crash.db", false, true)
	defer accessor.Close()

	accessor.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return agreeInstallDatabase(tx)
	}) // ignore error

	p := player{
		Round:  370,
		Period: 8,
		Step:   15,
	}

	raw := [100 * 1024]byte{}
	crypto.RandBytes(raw[:])
	persist(serviceLogger{Logger: logging.Base()}, accessor, p.Round, p.Period, p.Step, raw[:])
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		restore(serviceLogger{Logger: logging.Base()}, accessor)
	}
}

const randomizedEncodingMaxCollectionLen = 8 // instead of 32 used in codec_tester.go

func randomizeDiskState() (rr rootRouter, p player) {
	opts := []protocol.RandomizeObjectOption{
		protocol.RandomizeObjectWithMaxCollectionLen(randomizedEncodingMaxCollectionLen),
		protocol.RandomizeObjectSilenceAllocWarnings(),
	}
	p2, err := protocol.RandomizeObject(&player{}, opts...)
	if err != nil {
		return
	}

	rr2, err := protocol.RandomizeObject(&rootRouter{}, opts...)
	if err != nil {
		return
	}
	p = *(p2.(*player))
	p.OldDeadline = 0
	rr = *(rr2.(*rootRouter))
	return
}

// persistedTestActions covers every concrete action type so encoding tests
// exercise the msgp and reflection codecs on each of them.
func persistedTestActions() []action {
	return []action{
		noopAction{},
		networkAction{T: broadcast, Tag: protocol.AgreementVoteTag, UnauthenticatedVotes: []unauthenticatedVote{{}, {}}},
		networkAction{T: disconnect, Err: makeSerErrStr("test disconnect")},
		cryptoAction{T: verifyVote, Round: 100, Period: 2, Step: soft, TaskIndex: 7, Pinned: true},
		ensureAction{Certificate: Certificate{Round: 100}},
		stageDigestAction{Certificate: Certificate{Round: 101, Period: 3}},
		rezeroAction{Round: 102},
		pseudonodeAction{T: attest, Round: 103, Period: 1, Step: cert},
		checkpointAction{Round: 104, Period: 2, Step: cert, Err: makeSerErrStr("test checkpoint")},
	}
}

// encodeDiskStateReflect replicates the retired go-codec reflection encoder
// for crash state, so tests keep proving that the msgp encoder produces the
// exact bytes every past release wrote to the crash database.
func encodeDiskStateReflect(t timers.Clock[TimeoutType], rr rootRouter, p player, a []action) []byte {
	var s diskState

	children := make(map[round]*roundRouter)
	for rnd, rndRouter := range rr.Children {
		if rnd >= p.Round {
			children[rnd] = rndRouter
		}
	}
	if len(children) == 0 {
		rr.Children = nil
	} else {
		rr.Children = children
	}

	s.Router = protocol.EncodeReflect(rr)
	s.Player = protocol.EncodeReflect(p)
	s.Clock = t.Encode()
	s.ActionTypes = make([]actionType, len(a))
	s.Actions = make([][]byte, len(a))
	for i, act := range a {
		s.ActionTypes[i] = act.t()
		s.Actions[i] = protocol.EncodeReflect(act)
	}
	return protocol.EncodeReflect(s)
}

func TestRandomizedEncodingFullDiskState(t *testing.T) {
	partitiontest.PartitionTest(t)
	iterations := 1000
	if testing.Short() {
		iterations = 500
	}

	for i := 0; i < iterations; i++ {
		router, player := randomizeDiskState()
		a := persistedTestActions()
		clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
		log := makeServiceLogger(logging.Base())
		e1 := encodeDiskStateReflect(clock, router, player, a)
		e2 := encode(clock, router, player, a)
		require.Equalf(t, e1, e2, "msgp and go-codec encodings differ: len(reflect)=%v, len(msgp)=%v", len(e1), len(e2))
		_, rr2, p2, a2, err := decode(e1, clock, log)
		require.NoErrorf(t, err, "decoding failed")
		require.Equalf(t, a, a2, "decoded actions differ from the originals")
		// the decoded state must re-encode to the same canonical bytes
		e3 := encode(clock, rr2, p2, a2)
		require.Equalf(t, e1, e3, "re-encoding of decoded state differs")
	}

}

func TestCredentialHistoryAllocated(t *testing.T) {
	partitiontest.PartitionTest(t)
	router, player := randomizeDiskState()
	a := []action{}
	clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	log := makeServiceLogger(logging.Base())
	e1 := encode(clock, router, player, a)
	_, _, p2, _, err := decode(e1, clock, log)
	require.NoErrorf(t, err, "decoding failed")

	require.Len(t, p2.lowestCredentialArrivals.history, dynamicFilterCredentialArrivalHistory)
	emptyHistory := makeCredentialArrivalHistory(dynamicFilterCredentialArrivalHistory)
	require.Equalf(t, p2.lowestCredentialArrivals, emptyHistory, "credential arrival history isn't empty")
}

func BenchmarkRandomizedEncode(b *testing.B) {
	clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	router, player := randomizeDiskState()
	a := []action{}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		encode(clock, router, player, a)
	}
}

func BenchmarkRandomizedDecode(b *testing.B) {
	clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	router, player := randomizeDiskState()
	a := []action{}
	ds := encode(clock, router, player, a)
	log := makeServiceLogger(logging.Base())
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		decode(ds, clock, log)
	}
}

func TestEmptyMapDeserialization(t *testing.T) {
	partitiontest.PartitionTest(t)
	var rr, rr1 rootRouter
	rr.Children = make(map[basics.Round]*roundRouter)
	e := protocol.Encode(&rr)
	err := protocol.Decode(e, &rr1)
	require.NoError(t, err)
	require.NotNil(t, rr1.Children)

	var v, v1 voteTracker
	v.Equivocators = make(map[basics.Address]equivocationVote)
	ve := protocol.Encode(&v)
	err = protocol.Decode(ve, &v1)
	require.NoError(t, err)
	require.NotNil(t, v1.Equivocators)
}

func TestDecodeErrs(t *testing.T) {
	partitiontest.PartitionTest(t)
	clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	ce := clock.Encode()
	log := makeServiceLogger(logging.Base())
	player := player{Round: 350, Step: soft, Deadline: Deadline{Duration: time.Duration(23) * time.Second, Type: TimeoutDeadline}}
	router := makeRootRouter(player)
	pe := protocol.Encode(&player)
	re := protocol.Encode(&router)

	// diskState decoding failure
	{
		type diskState struct {
			UnexpectedDiskField int64
		}
		uds := diskState{UnexpectedDiskField: 5}
		udse := protocol.EncodeReflect(uds)
		_, _, _, _, err := decode(udse, clock, log)
		require.ErrorContains(t, err, "UnexpectedDiskField")

	}

	// player decoding failure
	{
		type player struct {
			UnexpectedPlayerField int64
		}
		p := player{UnexpectedPlayerField: 3}
		pe := protocol.EncodeReflect(p)
		ds := diskState{Player: pe, Router: re, Clock: ce}
		dse := protocol.EncodeReflect(ds)
		_, _, _, _, err := decode(dse, clock, log)
		require.ErrorContains(t, err, "UnexpectedPlayerField")
	}

	// router decoding failure
	{
		type rootRouter struct {
			UnexpectedRouterField int64
		}
		router := rootRouter{UnexpectedRouterField: 5}
		re := protocol.EncodeReflect(router)
		ds := diskState{Player: pe, Router: re, Clock: ce}
		dse := protocol.EncodeReflect(ds)
		_, _, _, _, err := decode(dse, clock, log)
		require.ErrorContains(t, err, "UnexpectedRouterField")
	}
}
