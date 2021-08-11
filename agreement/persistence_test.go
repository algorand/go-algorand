// Copyright (C) 2019-2021 Algorand, Inc.
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/timers"
	"github.com/algorand/go-deadlock"
)

func TestAgreementSerialization(t *testing.T) {
	// todo : we need to deserialize some more meaningfull state.
	//clock := timers.MakeMonotonicClock(time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	clockManager := makeClockManager(&timers.Monotonic{})
	rnd := makeRoundRandomBranch(350)
	//clockManager.m[rnd] = clock
	clockManager.setZero(rnd)
	status := &player{Round: rnd, Step: soft, Deadline: time.Duration(23) * time.Second}
	router := makeRootRouter(status)
	a := []action{}

	encodedBytes := encode(clockManager, router, status, a)

	t0 := makeClockManager(&timers.Monotonic{})
	clockM2, router2, status2, a2, err := decode(encodedBytes, t0)
	require.NoError(t, err)
	// clear clockManager mutex so equal check will work
	clockManager.mu, clockM2.mu = deadlock.Mutex{}, deadlock.Mutex{}
	require.Equalf(t, clockManager, clockM2, "Clock wasn't serialized/deserialized correctly")
	require.Equalf(t, router, router2, "Router wasn't serialized/deserialized correctly")
	require.Equalf(t, status, status2, "Status wasn't serialized/deserialized correctly")
	require.Equalf(t, a, a2, "Action wasn't serialized/deserialized correctly")
}

func TestAgreementSerializationPipeline(t *testing.T) {
	// todo : we need to deserialize some more meaningfull state.
	clockManager := makeClockManager(&timers.Monotonic{})
	//clock := timers.MakeMonotonicClock(time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	rnd := makeRoundRandomBranch(350)
	//clockManager.m[rnd] = clock
	clockManager.setZero(rnd)
	status := &pipelinePlayer{
		FirstUncommittedRound: 349,
		Players: map[round]*player{
			rnd: &player{Round: rnd, Step: soft, Deadline: time.Duration(23) * time.Second}},
	}
	router := makeRootRouter(status)
	a := []action{}

	encodedBytes := encode(clockManager, router, status, a)

	t0 := makeClockManager(&timers.Monotonic{})
	clockM2, router2, status2, a2, err := decode(encodedBytes, t0)
	require.NoError(t, err)
	// clear clockManager mutex so equal check will work
	clockManager.mu, clockM2.mu = deadlock.Mutex{}, deadlock.Mutex{}
	require.Equalf(t, clockManager, clockM2, "Clock wasn't serialized/deserialized correctly")
	require.Equalf(t, status, status2, "Status wasn't serialized/deserialized correctly")
	require.Equalf(t, router, router2, "Router wasn't serialized/deserialized correctly")
	require.Equalf(t, a, a2, "Action wasn't serialized/deserialized correctly")
}

func BenchmarkAgreementSerialization(b *testing.B) {
	// todo : we need to deserialize some more meaningfull state.
	b.SkipNow()

	clockManager := makeClockManager(&timers.Monotonic{})
	clock := timers.MakeMonotonicClock(time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	rnd := makeRoundRandomBranch(350)
	clockManager.m[rnd] = clock
	status := pipelinePlayer{
		FirstUncommittedRound: 349,
		Players: map[round]*player{
			rnd: &player{Round: rnd, Step: soft, Deadline: time.Duration(23) * time.Second}},
	}
	router := makeRootRouter(&status)
	a := []action{}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		encode(clockManager, router, &status, a)
	}
}

func BenchmarkAgreementDeserialization(b *testing.B) {
	// todo : we need to deserialize some more meaningfull state.
	b.SkipNow()

	clockManager := makeClockManager(&timers.Monotonic{})
	clock := timers.MakeMonotonicClock(time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	rnd := makeRoundRandomBranch(350)
	clockManager.m[rnd] = clock
	status := pipelinePlayer{
		FirstUncommittedRound: 349,
		Players: map[round]*player{
			rnd: &player{Round: rnd, Step: soft, Deadline: time.Duration(23) * time.Second}},
	}
	router := makeRootRouter(&status)
	a := []action{}

	encodedBytes := encode(clockManager, router, &status, a)
	t0 := makeClockManager(&timers.Monotonic{})

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		decode(encodedBytes, t0)
	}
}

func TestAgreementPersistence(t *testing.T) {
	accessor, err := db.MakeAccessor(t.Name()+"_crash.db", false, true)
	require.NoError(t, err)
	defer accessor.Close()

	accessor.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return agreeInstallDatabase(tx)
	}) // ignore error

	p := player{
		Round:  makeRound(370),
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
		Round:  makeRound(370),
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
		Round:  makeRound(370),
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

func TestPlayerSerialization(t *testing.T) {
	rnd := makeRoundRandomBranch(350)

	p := &player{Round: rnd, Period: 8, Step: 15}
	buf := encodePlayer(p)
	p2, err := decodePlayer(buf)
	require.NoError(t, err)
	assert.Equal(t, p, p2)

	status := &pipelinePlayer{
		FirstUncommittedRound: 349,
		Players: map[round]*player{
			rnd: &player{Round: rnd, Step: soft, Deadline: time.Duration(23) * time.Second}},
	}
	buf = encodePlayer(status)
	status2, err := decodePlayer(buf)
	require.NoError(t, err)
	assert.Equal(t, status, status2)
}
