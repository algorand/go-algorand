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

package metrics

import (
	"time"

	"github.com/algorand/go-deadlock"
)

// Gauge represent a single gauge variable.
type Gauge struct {
	deadlock.Mutex
	name          string
	description   string
	labels        map[string]int       // map each label ( i.e. httpErrorCode ) to an index.
	valuesIndices map[int]*gaugeValues // maps each set of labels into a concrete gauge
}

type gaugeValues struct {
	gauge           float64
	timestamp       time.Time
	labels          map[string]string
	formattedLabels string
}
