package account

import (
	"fmt"
	"testing"

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
		for n := 0; n < b.N; n++ {
			for key := 0; key < numKeys; key++ {
				p := makeTestParticipation(key, basics.Round(0), basics.Round(1000000), 3)
				registry.Insert(p)
			}
		}
	})

	// The first call to Register updates the DB.
	b.Run(fmt.Sprintf("KeyRegistered_%d", numKeys), func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			for key := 0; key < numKeys; key++ {
				p := makeTestParticipation(key, basics.Round(0), basics.Round(1000000), 3)

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
		for n := 0; n < b.N; n++ {
			for key := 0; key < numKeys; key++ {
				p := makeTestParticipation(key, basics.Round(0), basics.Round(1000000), 3)
				registry.Register(p.ID(), 50)
			}
		}
	})
}

func BenchmarkKeyRegistration1(b *testing.B)  { benchmarkKeyRegistration(1, b) }
func BenchmarkKeyRegistration5(b *testing.B)  { benchmarkKeyRegistration(5, b) }
func BenchmarkKeyRegistration10(b *testing.B) { benchmarkKeyRegistration(10, b) }
func BenchmarkKeyRegistration50(b *testing.B) { benchmarkKeyRegistration(50, b) }
