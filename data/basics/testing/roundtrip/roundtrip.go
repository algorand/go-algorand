// Copyright (C) 2019-2025 Algorand, Inc.
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

package roundtrip

import (
	"reflect"
	"testing"

	"pgregory.net/rapid"

	"github.com/algorand/go-algorand/protocol"
)

const defaultRandomCount = 100

// CheckOption configures the behavior of Check.
type CheckOption interface {
	apply(*checkConfig)
}

type checkConfig struct {
	randomCount    *int
	randomOpts     []protocol.RandomizeObjectOption
	rapidGen       interface{} // *rapid.Generator[A], stored as interface{} to avoid type parameters
	useRapid       bool
	skipNearZeros  bool
}

type randomCountOption int

func (n randomCountOption) apply(cfg *checkConfig) {
	count := int(n)
	cfg.randomCount = &count
}

type randomOptsOption []protocol.RandomizeObjectOption

func (opts randomOptsOption) apply(cfg *checkConfig) {
	cfg.randomOpts = append(cfg.randomOpts, opts...)
}

type rapidGenOption struct {
	gen interface{}
}

func (r rapidGenOption) apply(cfg *checkConfig) {
	cfg.rapidGen = r.gen
	cfg.useRapid = true
}

// Opts configures round-trip checking behavior.
// The first argument specifies the number of random test cases to generate.
// Additional protocol.RandomizeObjectOption arguments can be passed to customize randomization.
func Opts(count int, opts ...protocol.RandomizeObjectOption) CheckOption {
	return multiOption{randomCountOption(count), randomOptsOption(opts)}
}

// NoRandomCases disables RandomizeObject testing (but still runs NearZeros).
// Use this when RandomizeObject generates invalid values for constrained types.
// Combine with NoNearZeros() to disable all automatic testing.
func NoRandomCases() CheckOption {
	return randomCountOption(0)
}

type skipNearZerosOption struct{}

func (skipNearZerosOption) apply(cfg *checkConfig) {
	cfg.skipNearZeros = true
}

// NoNearZeros disables NearZeros testing, only using RandomizeObject for random variants.
// Use this for non-struct types (maps, slices) where NearZeros doesn't apply.
func NoNearZeros() CheckOption {
	return skipNearZerosOption{}
}

// WithRapid specifies a rapid.Generator to use for property-based testing.
// If provided, rapid.Check will be used instead of protocol.RandomizeObject (runs 100 tests).
func WithRapid[A any](gen *rapid.Generator[A]) CheckOption {
	return rapidGenOption{gen: gen}
}

type multiOption []CheckOption

func (m multiOption) apply(cfg *checkConfig) {
	for _, opt := range m {
		opt.apply(cfg)
	}
}

// Check verifies that converting from A -> B -> A yields the original value.
// By default, tests the provided example, all NearZeros variants (one per field),
// and 100 randomly generated values using protocol.RandomizeObject.
// Use WithRapid to provide a custom rapid.Generator for property-based testing.
// Use NoRandomCases to disable RandomizeObject (still runs NearZeros).
// Use NoNearZeros to disable NearZeros (for non-struct types like maps).
// Use Opts to customize the number of random tests or pass RandomizeObjectOptions.
func Check[A any, B any](t *testing.T, a A, toB func(A) B, toA func(B) A, opts ...CheckOption) bool {
	cfg := checkConfig{}
	for _, opt := range opts {
		opt.apply(&cfg)
	}

	// Test the provided example first
	if !checkOne(t, a, toB, toA) {
		t.Errorf("Round-trip failed for provided example: %+v", a)
		return false
	}

	// Use rapid property testing if generator provided
	if cfg.useRapid {
		gen, ok := cfg.rapidGen.(*rapid.Generator[A])
		if !ok {
			t.Errorf("Invalid rapid generator type")
			return false
		}

		// Run rapid property tests (runs 100 tests by default)
		// Note: rapid.Check controls the count, not us
		passed := true
		rapid.Check(t, func(t1 *rapid.T) {
			randA := gen.Draw(t1, "value")
			if !checkOne(t, randA, toB, toA) {
				t.Errorf("Round-trip failed for rapid-generated value: %+v", randA)
				passed = false
			}
		})
		return passed
	}

	// Test NearZeros (one test per field) - comprehensive and deterministic
	// Skip if explicitly disabled
	if !cfg.skipNearZeros {
		nearZeroValues := NearZeros(t, a)
		for i, nzA := range nearZeroValues {
			if !checkOne(t, nzA, toB, toA) {
				t.Errorf("Round-trip failed for NearZero variant %d: %+v", i, nzA)
				return false
			}
		}
	}

	// Determine random count for RandomizeObject testing
	randomCount := defaultRandomCount
	if cfg.randomCount != nil {
		randomCount = *cfg.randomCount
	}

	// Test with RandomizeObject for additional coverage
	var template A
	for i := 0; i < randomCount; i++ {
		randObj, err := protocol.RandomizeObject(&template, cfg.randomOpts...)
		if err != nil {
			t.Logf("Failed to randomize object (variant %d): %v", i, err)
			continue
		}

		// Type assert the result back to *A, then dereference
		randPtr, ok := randObj.(*A)
		if !ok {
			t.Errorf("Type assertion failed for random variant %d", i)
			return false
		}
		randA := *randPtr

		if !checkOne(t, randA, toB, toA) {
			t.Errorf("Round-trip failed for random variant %d: %+v", i, randA)
			return false
		}
	}

	return true
}

func checkOne[A any, B any](t *testing.T, a A, toB func(A) B, toA func(B) A) bool {
	b := toB(a)
	a2 := toA(b)
	if !reflect.DeepEqual(a, a2) {
		t.Logf("Round-trip mismatch:\n  Original: %+v\n  After:    %+v", a, a2)
		return false
	}
	return true
}
