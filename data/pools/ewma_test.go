// Copyright (C) 2019 Algorand, Inc.
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

package pools

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMakeFeeTrackerError(t *testing.T) {
	_, err := NewEMA(-5)
	assert.Error(t, err)

	_, err = NewEMA(5)
	assert.Error(t, err)

	ft, err := NewEMA(0.364)
	assert.NoError(t, err)

	assert.Equal(t, ft.alpha, 0.364)
	assert.Zero(t, ft.value)
}

func TestEWMA_Same_Number(t *testing.T) {
	alpha := 0.4151165
	ft, err := NewEMA(alpha)
	assert.NoError(t, err)

	assert.Equal(t, ft.alpha, alpha)
	assert.Zero(t, ft.value)

	ft.Add(5)
	ft.Add(5)
	ft.Add(5)
	ft.Add(5)
	ft.Add(5)
	ft.Add(5)

	// Avg of N times Y is Y regardless of alpha
	assert.Equal(t, uint64(5), ft.Value())

}

func TestEWMA_Number(t *testing.T) {
	alpha := 2 / 6.0
	ft, err := NewEMA(alpha)
	assert.NoError(t, err)

	assert.Equal(t, ft.alpha, alpha)
	assert.Zero(t, ft.value)

	ft.Add(1)
	ft.Add(2)
	ft.Add(3)
	ft.Add(4)
	ft.Add(5)

	assert.Equal(t, uint64(3), ft.Value())

}

func TestEWMA_Number2(t *testing.T) {
	alpha := 0.5
	ft, err := NewEMA(alpha)
	assert.NoError(t, err)

	assert.Equal(t, ft.alpha, alpha)
	assert.Zero(t, ft.value)

	ft.Add(-1)
	ft.Add(1)
	ft.Add(10)

	assert.Equal(t, uint64(5), ft.Value())

}
