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

package main

import (
	"fmt"
	"testing"
)

func TestMetricsFetcher(t *testing.T) {
	// this test function was meant for local development test and not as an official unit test.
	t.Skip()
	//host := "3.81.68.74"
	host := "telemetry.algodev.network"
	f := makePromMetricFetcher(host)
	results, err := f.getMetric("max(algod_ledger_round)")
	if err != nil {
		t.Fatalf("failed get metric : %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("failed get metric : %v", results)
	}
	result, err := f.getSingleValue(results)
	if err != nil {
		t.Fatalf("failed get metric : %v", err)
	}
	fmt.Printf("Received round %v\n", result)
}
