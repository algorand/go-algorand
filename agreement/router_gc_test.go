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
	"maps"
	"math/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// rebuildRootChildren is the garbage collection rootRouter.update used to perform: select
// the survivors into a freshly allocated map. Kept here as the reference the in-place
// deletion is checked against.
func rebuildRootChildren(in map[round]*roundRouter, stateRound round) map[round]*roundRouter {
	children := make(map[round]*roundRouter)
	for r, c := range in {
		if r+credentialRoundLag >= stateRound {
			children[r] = c
		}
	}
	return children
}

// rebuildRoundChildren is the same for roundRouter.update.
func rebuildRoundChildren(in map[period]*periodRouter, statePeriod period) map[period]*periodRouter {
	children := make(map[period]*periodRouter)
	for p, c := range in {
		if p+1 >= statePeriod {
			children[p] = c
		} else if p <= 1 {
			children[p] = c
		}
	}
	return children
}

// TestRouterUpdateGarbageCollection checks that deleting stale children in place keeps
// exactly the children the previous (moving to a new map) approach kept.
//
// The retention rule turns on a single boundary - how far a child's round or period lags
// the player's - so the sweep below covers every combination on and around it exhaustively
// rather than hoping random draws land there. A smaller randomized pass follows, for the
// one thing a single-child sweep cannot exercise: deleting several entries while ranging
// over the map.
func TestRouterUpdateGarbageCollection(t *testing.T) {
	partitiontest.PartitionTest(t)

	// rootRouter: a child at round r survives while r+credentialRoundLag >= state.Round.
	// Sweeping to 3x the lag puts the boundary well inside the range in both directions.
	maxRound := 3 * credentialRoundLag
	for stateRound := round(0); stateRound <= maxRound; stateRound++ {
		for childRound := round(0); childRound <= maxRound; childRound++ {
			// arg is the round update() is asked to route to, which it creates a child
			// for before collecting; vary it across the interesting positions
			for _, arg := range []round{0, childRound, stateRound, maxRound} {
				root := new(rootRouter)
				root.Children = map[round]*roundRouter{childRound: new(roundRouter)}

				seeded := maps.Clone(root.Children)
				if seeded[arg] == nil {
					seeded[arg] = new(roundRouter)
				}
				want := rebuildRootChildren(seeded, stateRound)

				root.update(player{Round: stateRound}, arg, true)
				require.Equal(t, slices.Sorted(maps.Keys(want)), slices.Sorted(maps.Keys(root.Children)),
					"rootRouter children differ: state.Round=%d child=%d arg=%d", stateRound, childRound, arg)
			}
		}
	}

	// roundRouter: a child at period p survives while p+1 >= state.Period, and periods 0
	// and 1 are kept unconditionally, so the range only needs to reach past both rules.
	const maxPeriod = period(6)
	for statePeriod := period(0); statePeriod <= maxPeriod; statePeriod++ {
		for childPeriod := period(0); childPeriod <= maxPeriod; childPeriod++ {
			for _, arg := range []period{0, childPeriod, statePeriod, maxPeriod} {
				rr := new(roundRouter)
				rr.Children = map[period]*periodRouter{childPeriod: new(periodRouter)}

				seeded := maps.Clone(rr.Children)
				if seeded[arg] == nil {
					seeded[arg] = new(periodRouter)
				}
				want := rebuildRoundChildren(seeded, statePeriod)

				rr.update(player{Period: statePeriod}, arg, true)
				require.Equal(t, slices.Sorted(maps.Keys(want)), slices.Sorted(maps.Keys(rr.Children)),
					"roundRouter children differ: state.Period=%d child=%d arg=%d", statePeriod, childPeriod, arg)
			}
		}
	}

	// Several children at once, so that a collection pass deletes more than one entry
	// while ranging over the map.
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 200; i++ {
		stateRound := round(rng.Intn(int(maxRound)))
		arg := round(rng.Intn(int(maxRound)))
		root := new(rootRouter)
		root.Children = make(map[round]*roundRouter)
		for j := 0; j < 1+rng.Intn(15); j++ {
			root.Children[round(rng.Intn(int(maxRound)))] = new(roundRouter)
		}
		seeded := maps.Clone(root.Children)
		if seeded[arg] == nil {
			seeded[arg] = new(roundRouter)
		}
		want := rebuildRootChildren(seeded, stateRound)

		root.update(player{Round: stateRound}, arg, true)
		require.Equal(t, slices.Sorted(maps.Keys(want)), slices.Sorted(maps.Keys(root.Children)),
			"rootRouter children differ with %d children: state.Round=%d arg=%d", len(seeded), stateRound, arg)
	}
}

// TestRouterUpdateKeepsChildIdentity checks that garbage collection preserves the router
// instances themselves, not merely their keys: a surviving child must be the same object,
// since it carries the state machine's accumulated state.
func TestRouterUpdateKeepsChildIdentity(t *testing.T) {
	partitiontest.PartitionTest(t)

	root := new(rootRouter)
	root.Children = make(map[round]*roundRouter)
	survivor := new(roundRouter)
	root.Children[100] = survivor
	root.Children[1] = new(roundRouter) // far enough back to be collected

	root.update(player{Round: 100}, 100, true)

	require.Same(t, survivor, root.Children[100], "surviving child must be the same instance")
	require.NotContains(t, root.Children, round(1), "stale child must be collected")
}

// BenchmarkRouterUpdate measures the per-event cost of routing state garbage collection.
//
// rootRouter.update and roundRouter.update run on every event routed through the state
// machine tree -- submitTop and dispatch both call them with gc set -- so their allocation
// count is multiplied by the agreement message rate. Reported allocs/op is the figure of
// interest: collecting in place rather than rebuilding the children map, and not creating
// a child that collection would immediately delete, should make steady-state updates
// allocation-free.
func BenchmarkRouterUpdate(b *testing.B) {
	b.Run("root", func(b *testing.B) {
		router := new(rootRouter)
		router.Children = make(map[round]*roundRouter)
		// the rounds a steady-state node keeps: everything within credentialRoundLag
		const current = round(1000)
		for r := current; r+credentialRoundLag >= current; r-- {
			router.Children[r] = new(roundRouter)
		}
		state := player{Round: current}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// what submitTop does for every event
			router.update(state, 0, true)
		}
	})

	b.Run("round", func(b *testing.B) {
		router := new(roundRouter)
		router.Children = make(map[period]*periodRouter)
		const current = period(3)
		for p := period(0); p <= current; p++ {
			router.Children[p] = new(periodRouter)
		}
		state := player{Period: current}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// what roundRouter.dispatch does for every event it routes
			router.update(state, current, true)
		}
	})
}
