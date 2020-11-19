// Copyright (C) 2019-2020 Algorand, Inc.
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

package telemetryspec

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTranscationProcessingTimeDistibutionFormatting(t *testing.T) {
	var processingTime transcationProcessingTimeDistibution
	processingTime.AddTransaction(50000 * time.Nanosecond)
	processingTime.AddTransaction(80000 * time.Nanosecond)
	processingTime.AddTransaction(120000 * time.Nanosecond)
	processingTime.AddTransaction(150000 * time.Nanosecond)
	processingTime.AddTransaction(180000 * time.Nanosecond)
	processingTime.AddTransaction(950000 * time.Nanosecond)
	processingTime.AddTransaction(2 * time.Millisecond)
	bytes, err := processingTime.MarshalText()
	require.NoError(t, err)
	require.Equal(t, []byte("2,3,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"), bytes)

	container := struct {
		ProcessingTime transcationProcessingTimeDistibution
	}{ProcessingTime: processingTime}

	bytes, err = json.Marshal(container)
	require.NoError(t, err)
	require.Equal(t, []byte("{\"ProcessingTime\":\"2,3,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0\"}"), bytes)
}
