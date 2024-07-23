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

package account

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
)

func benchmarkKeyRegistration(numKeys int, b *testing.B) {
	// setup
	rootDB, err := db.OpenPair(b.Name(), true)
	if err != nil {
		b.Fail()
	}
	registry, err := makeParticipationRegistry(rootDB, logging.TestingLog(b))
	if err != nil {
		b.Fail()
	}

	// Insert records so that we can t
	b.Run(fmt.Sprintf("KeyInsert_%d", numKeys), func(b *testing.B) {
		a := require.New(b)
		for n := 0; n < b.N; n++ {
			for key := 0; key < numKeys; key++ {
				p := makeTestParticipation(a, key, basics.Round(0), basics.Round(1000000), 3)
				registry.Insert(p)
			}
		}
	})

	// The first call to Register updates the DB.
	b.Run(fmt.Sprintf("KeyRegistered_%d", numKeys), func(b *testing.B) {
		a := require.New(b)
		for n := 0; n < b.N; n++ {
			for key := 0; key < numKeys; key++ {
				p := makeTestParticipation(a, key, basics.Round(0), basics.Round(1000000), 3)

				// Unfortunately we need to repeatedly clear out the registration fields to ensure the
				// db update runs each time this is called.
				record := registry.cache[p.ID()]
				record.EffectiveFirst = 0
				record.EffectiveLast = 0
				registry.cache[p.ID()] = record
				registry.Register(p.ID(), 50)
			}
		}
	})

	// The keys should now be updated, so Register is a no-op.
	b.Run(fmt.Sprintf("NoOp_%d", numKeys), func(b *testing.B) {
		a := require.New(b)
		for n := 0; n < b.N; n++ {
			for key := 0; key < numKeys; key++ {
				p := makeTestParticipation(a, key, basics.Round(0), basics.Round(1000000), 3)
				registry.Register(p.ID(), 50)
			}
		}
	})
}

func BenchmarkKeyRegistration1(b *testing.B)  { benchmarkKeyRegistration(1, b) }
func BenchmarkKeyRegistration5(b *testing.B)  { benchmarkKeyRegistration(5, b) }
func BenchmarkKeyRegistration10(b *testing.B) { benchmarkKeyRegistration(10, b) }
func BenchmarkKeyRegistration50(b *testing.B) { benchmarkKeyRegistration(50, b) }
