// Copyright (C) 2019-2024 Algorand, Inc.
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

	encodedBytes := encode(clock, router, status, a, false)

	t0 := timers.MakeMonotonicClock[TimeoutType](time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC))
	log := makeServiceLogger(logging.Base())
	clock2, router2, status2, a2, err := decode(encodedBytes, t0, log, false)
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

	encodedBytes2 := encode(clock3, router3, status3, a3, false)

	t1 := timers.MakeMonotonicClock[TimeoutType](time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC))
	clock4, router4, status4, a4, err := decode(encodedBytes2, t1, log, false)
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
		encode(clock, router, status, a, false)
	}
}

func BenchmarkAgreementDeserialization(b *testing.B) {
	// todo : we need to deserialize some more meaningful state.
	b.SkipNow()

	clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	status := player{Round: 350, Step: soft, Deadline: Deadline{Duration: time.Duration(23) * time.Second, Type: TimeoutDeadline}}
	router := makeRootRouter(status)
	a := []action{}

	encodedBytes := encode(clock, router, status, a, false)
	t0 := timers.MakeMonotonicClock[TimeoutType](time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC))
	log := makeServiceLogger(logging.Base())
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		decode(encodedBytes, t0, log, false)
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

func randomizeDiskState() (rr rootRouter, p player) {
	p2, err := protocol.RandomizeObject(&player{})
	if err != nil {
		return
	}

	rr2, err := protocol.RandomizeObject(&rootRouter{})
	if err != nil {
		return
	}
	p = *(p2.(*player))
	p.OldDeadline = 0
	rr = *(rr2.(*rootRouter))
	return
}

func TestRandomizedEncodingFullDiskState(t *testing.T) {
	partitiontest.PartitionTest(t)
	for i := 0; i < 5000; i++ {
		router, player := randomizeDiskState()
		a := []action{}
		clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
		log := makeServiceLogger(logging.Base())
		e1 := encode(clock, router, player, a, true)
		e2 := encode(clock, router, player, a, false)
		require.Equalf(t, e1, e2, "msgp and go-codec encodings differ: len(msgp)=%v, len(reflect)=%v", len(e1), len(e2))
		_, rr1, p1, _, err1 := decode(e1, clock, log, true)
		_, rr2, p2, _, err2 := decode(e1, clock, log, false)
		require.NoErrorf(t, err1, "reflect decoding failed")
		require.NoErrorf(t, err2, "msgp decoding failed")
		require.Equalf(t, rr1, rr2, "rootRouters decoded differently")
		require.Equalf(t, p1, p2, "players decoded differently")
	}

}

func TestCredentialHistoryAllocated(t *testing.T) {
	partitiontest.PartitionTest(t)
	router, player := randomizeDiskState()
	a := []action{}
	clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	log := makeServiceLogger(logging.Base())
	e1 := encode(clock, router, player, a, true)
	e2 := encode(clock, router, player, a, false)
	require.Equalf(t, e1, e2, "msgp and go-codec encodings differ: len(msgp)=%v, len(reflect)=%v", len(e1), len(e2))
	_, _, p1, _, err1 := decode(e1, clock, log, true)
	_, _, p2, _, err2 := decode(e1, clock, log, false)
	require.NoErrorf(t, err1, "reflect decoding failed")
	require.NoErrorf(t, err2, "msgp decoding failed")

	require.Len(t, p1.lowestCredentialArrivals.history, dynamicFilterCredentialArrivalHistory)
	require.Len(t, p2.lowestCredentialArrivals.history, dynamicFilterCredentialArrivalHistory)
	emptyHistory := makeCredentialArrivalHistory(dynamicFilterCredentialArrivalHistory)
	require.Equalf(t, p1.lowestCredentialArrivals, emptyHistory, "credential arrival history isn't empty")
	require.Equalf(t, p2.lowestCredentialArrivals, emptyHistory, "credential arrival history isn't empty")
}

func BenchmarkRandomizedEncode(b *testing.B) {
	clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	router, player := randomizeDiskState()
	a := []action{}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		encode(clock, router, player, a, false)
	}
}

func BenchmarkRandomizedDecode(b *testing.B) {
	clock := timers.MakeMonotonicClock[TimeoutType](time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	router, player := randomizeDiskState()
	a := []action{}
	ds := encode(clock, router, player, a, false)
	log := makeServiceLogger(logging.Base())
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		decode(ds, clock, log, false)
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

func TestDecodeFailures(t *testing.T) {
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
		_, _, _, _, err := decode(udse, clock, log, false)
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
		_, _, _, _, err := decode(dse, clock, log, false)
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
		_, _, _, _, err := decode(dse, clock, log, false)
		require.ErrorContains(t, err, "UnexpectedRouterField")
	}
}
