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
	"bufio"
	"fmt"
	"io"
	"os"
)

type roundPoller struct {
	telemetryHost string
}

func readHostFile(telemetryHostFile string) (bytes []byte, err error) {
	file, err := os.Open(telemetryHostFile)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	reader := bufio.NewReader(file)
	line, _, _ := reader.ReadLine()

	if err == io.EOF {
		return []byte(line), nil

	}
	if err != io.EOF && err != nil {
		return nil, err
	}
	return []byte(line), nil

}

func makeRoundPoller(telemetryHostFile string) *roundPoller {
	if telemetryHostFile == "" {
		return nil
	}
	hostNameBytes, err := readHostFile(telemetryHostFile)
	if err != nil {
		fmt.Printf("Failed to read '%s' : %v\n", telemetryHostFile, err)
		return nil
	}

	return &roundPoller{
		telemetryHost: string(hostNameBytes),
	}
}

func (r *roundPoller) getRound() (round uint64, err error) {
	fetcher := makePromMetricFetcher(r.telemetryHost)
	results, err := fetcher.getMetric("max(algod_ledger_round)")
	if err != nil {
		return 0, err
	}
	result, err := fetcher.getSingleValue(results)
	if err != nil {
		return 0, err
	}
	val := uint64(result)

	return val, nil
}
