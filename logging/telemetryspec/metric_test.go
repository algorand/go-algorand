// Copyright (C) 2019-2022 Algorand, Inc.
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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestTransactionProcessingTimeDistibutionFormatting(t *testing.T) {
	partitiontest.PartitionTest(t)
	var processingTime transactionProcessingTimeDistibution
	processingTime.AddTransaction(50000 * time.Nanosecond)
	processingTime.AddTransaction(80000 * time.Nanosecond)
	processingTime.AddTransaction(120000 * time.Nanosecond)
	processingTime.AddTransaction(150000 * time.Nanosecond)
	processingTime.AddTransaction(180000 * time.Nanosecond)
	processingTime.AddTransaction(950000 * time.Nanosecond)
	processingTime.AddTransaction(2 * time.Millisecond)
	bytes, err := processingTime.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, []byte("[2,3,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"), bytes)

	container := struct {
		ProcessingTime transactionProcessingTimeDistibution
	}{ProcessingTime: processingTime}

	bytes, err = json.Marshal(container)
	require.NoError(t, err)
	require.Equal(t, []byte("{\"ProcessingTime\":[2,3,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"), bytes)
}

func TestAssembleBlockStatsString(t *testing.T) {
	partitiontest.PartitionTest(t)

	var abs AssembleBlockStats
	localType := reflect.TypeOf(abs)

	// Empty StateProofStats will not be reported. Set a filed to check it printed
	abs.StateProofStats.ProvenWeight = 1
	absString := abs.String()
	for f := 0; f < localType.NumField(); f++ {
		field := localType.Field(f)
		if field.Type.Kind() == reflect.Struct && field.Type.NumField() > 1 {
			for nf := 0; nf < field.Type.NumField(); nf++ {
				nestedField := field.Type.Field(nf)
				require.Contains(t, absString, nestedField.Name)
			}
			continue
		}
		require.Contains(t, absString, field.Name)
	}

	// Make sure the StateProofStats is not reported if they are empty
	abs.StateProofStats.ProvenWeight = 0
	absString = abs.String()
	for f := 0; f < localType.NumField(); f++ {
		field := localType.Field(f)
		if field.Name == "StateProofStats" {
			for nf := 0; nf < field.Type.NumField(); nf++ {
				nestedField := field.Type.Field(nf)
				require.NotContains(t, absString, nestedField.Name)
			}
			continue
		}
		require.Contains(t, absString, field.Name)
	}
}
