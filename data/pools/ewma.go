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
	"fmt"
)

// EWMA represents an exponentially moving average based on the following formula -
// 			EWMA(S_0) = S_0
// 			EWMA(S_n) = \alpha*S_n + (1-\alpha)*S_{n-1}
type EWMA struct {
	alpha   float64
	value   float64
	running bool
}

// NewEMA creates a new Exponentially Moving Average
func NewEMA(alpha float64) (*EWMA, error) {
	if alpha <= 0 || alpha > 1 {
		return nil, fmt.Errorf("alpha must be between 0 and 1")
	}
	return &EWMA{alpha: alpha}, nil
}

// Add adds a new sample to the EWMA
func (ewma *EWMA) Add(sample float64) {
	if !ewma.running {
		ewma.value = sample
		ewma.running = true
		return
	}
	ewma.value = ewma.alpha*sample + (1-ewma.alpha)*ewma.value
}

// Value returns the current EWMA value rounded to the nearest integer
func (ewma *EWMA) Value() uint64 {
	return uint64(ewma.value)
}
