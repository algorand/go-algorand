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

package fuzzer

import (
	"fmt"
	"os"
	"runtime/pprof"
	"testing"

	"github.com/stretchr/testify/require"
)

type ValidatorConfig struct {
	NetworkRunTicks     int
	NetworkRecoverTicks int
}

type Validator struct {
	config    *ValidatorConfig
	runResult *RunResult
	tb        testing.TB
}

func MakeValidator(conf *ValidatorConfig, tb testing.TB) *Validator {
	return &Validator{
		config: conf,
		tb:     tb,
	}
}

func (v *Validator) Go(netConfig *FuzzerConfig) {
	network := MakeFuzzer(*netConfig)
	require.NotNil(v.tb, network)

	network.Start()
	//_, runRes := network.Run(v.config.NetworkRunDuration /*time.Millisecond*5000*/, time.Millisecond*3000, time.Second)
	_, v.runResult = network.Run(v.config.NetworkRunTicks, v.config.NetworkRecoverTicks, 100)

	v.CheckNetworkStalled()
	network.Shutdown()
	v.CheckNetworkRecovery()
}

func (v *Validator) CheckNetworkStalled() {
	if v.runResult.NetworkStalled {
		pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
		require.Failf(v.tb, "No network activity detected", "Network has stalled.")
		os.Exit(1)
		return
	}
}

func (v *Validator) CheckNetworkRecovery() {
	if v.config.NetworkRecoverTicks <= 0 {
		return
	}
	require.Truef(v.tb, (v.runResult.PostRecoveryHighRound-v.runResult.PostRecoveryLowRound <= 1),
		"Initial Rounds %d-%d\nPre Recovery Rounds %d-%d\nPost Recovery Rounds %d-%d",
		v.runResult.StartLowRound, v.runResult.StartHighRound,
		v.runResult.PreRecoveryLowRound, v.runResult.PreRecoveryHighRound,
		v.runResult.PostRecoveryLowRound, v.runResult.PostRecoveryHighRound,
	)
	require.NotEqualf(v.tb, int(v.runResult.PreRecoveryHighRound), int(v.runResult.PostRecoveryHighRound),
		"Initial Rounds %d-%d\nPre Recovery Rounds %d-%d\nPost Recovery Rounds %d-%d",
		v.runResult.StartLowRound, v.runResult.StartHighRound,
		v.runResult.PreRecoveryLowRound, v.runResult.PreRecoveryHighRound,
		v.runResult.PostRecoveryLowRound, v.runResult.PostRecoveryHighRound,
	)
	if v.runResult.PreRecoveryHighRound != v.runResult.PreRecoveryLowRound {
		// network got disputed by the filters.
		fmt.Printf("%v partitioned the network ( %d - %d ), but recovered correctly reaching round %d\n", v.tb.Name(), v.runResult.PreRecoveryLowRound, v.runResult.PreRecoveryHighRound, v.runResult.PostRecoveryHighRound)
	} else {
		if v.runResult.PreRecoveryHighRound == v.runResult.StartLowRound {
			fmt.Printf("%v stalled the network, and the network reached round %d\n", v.tb.Name(), v.runResult.PostRecoveryHighRound)
		} else {
			fmt.Printf("%v did not partition the network, and the network reached round %d\n", v.tb.Name(), v.runResult.PostRecoveryHighRound)
		}
	}
}
