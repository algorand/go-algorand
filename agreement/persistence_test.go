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

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/testPartitioning"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/timers"
)

func TestAgreementSerialization(t *testing.T) {
	testPartitioning.PartitionTest(t)

	// todo : we need to deserialize some more meaningfull state.
	clock := timers.MakeMonotonicClock(time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	status := player{Round: 350, Step: soft, Deadline: time.Duration(23) * time.Second}
	router := makeRootRouter(status)
	a := []action{}

	encodedBytes := encode(clock, router, status, a)

	t0 := timers.MakeMonotonicClock(time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC))
	clock2, router2, status2, a2, err := decode(encodedBytes, t0)
	require.NoError(t, err)
	require.Equalf(t, clock, clock2, "Clock wasn't serialized/deserialized correctly")
	require.Equalf(t, router, router2, "Router wasn't serialized/deserialized correctly")
	require.Equalf(t, status, status2, "Status wasn't serialized/deserialized correctly")
	require.Equalf(t, a, a2, "Action wasn't serialized/deserialized correctly")
}

func BenchmarkAgreementSerialization(b *testing.B) {
	// todo : we need to deserialize some more meaningfull state.
	b.SkipNow()

	clock := timers.MakeMonotonicClock(time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	status := player{Round: 350, Step: soft, Deadline: time.Duration(23) * time.Second}
	router := makeRootRouter(status)
	a := []action{}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		encode(clock, router, status, a)
	}
}

func BenchmarkAgreementDeserialization(b *testing.B) {
	// todo : we need to deserialize some more meaningfull state.
	b.SkipNow()

	clock := timers.MakeMonotonicClock(time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	status := player{Round: 350, Step: soft, Deadline: time.Duration(23) * time.Second}
	router := makeRootRouter(status)
	a := []action{}

	encodedBytes := encode(clock, router, status, a)
	t0 := timers.MakeMonotonicClock(time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		decode(encodedBytes, t0)
	}
}

func TestAgreementPersistence(t *testing.T) {
	testPartitioning.PartitionTest(t)

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
