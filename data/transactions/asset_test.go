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

package transactions

import (
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestAxferWellFormedErrors(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cases := []struct {
		axfer         AssetTransferTxnFields
		expectedError string
	}{
		{
			axfer: AssetTransferTxnFields{
				XferAsset:     basics.AssetIndex(0),
				AssetAmount:   0,
				AssetReceiver: basics.Address{},
			},
		},
		{
			axfer: AssetTransferTxnFields{
				XferAsset:     basics.AssetIndex(0),
				AssetAmount:   1,
				AssetReceiver: basics.Address{0x01},
			},
			expectedError: "asset ID cannot be zero",
		},
		{
			axfer: AssetTransferTxnFields{
				XferAsset:    basics.AssetIndex(1),
				AssetAmount:  0,
				AssetSender:  basics.Address{0x01},
				AssetCloseTo: basics.Address{0x02},
			},
			expectedError: "cannot close asset by clawback",
		},
	}

	for i, ax := range cases {
		name := fmt.Sprintf("axfer_i=%d", i)
		if ax.expectedError != "" {
			name = ax.expectedError
		}
		t.Run(name, func(t *testing.T) {
			err := ax.axfer.wellFormed()
			if ax.expectedError != "" {
				require.ErrorContains(t, err, ax.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAcfgWellFormedErrors(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cv18 := protocol.ConsensusV18
	cv20 := protocol.ConsensusV20
	cv28 := protocol.ConsensusV28

	cases := []struct {
		acfg          AssetConfigTxnFields
		cv            protocol.ConsensusVersion
		expectedError string
	}{
		{
			acfg: AssetConfigTxnFields{
				AssetParams: basics.AssetParams{
					AssetName: strings.Repeat("A", 33),
				},
			},
			cv:            cv18,
			expectedError: "transaction asset name too big: 33 > 32",
		},
		{
			acfg: AssetConfigTxnFields{
				AssetParams: basics.AssetParams{
					UnitName: strings.Repeat("B", 9),
				},
			},
			expectedError: "transaction asset unit name too big: 9 > 8",
		},
		{
			acfg: AssetConfigTxnFields{
				AssetParams: basics.AssetParams{
					URL: strings.Repeat("C", 33),
				},
			},
			cv:            cv18,
			expectedError: "transaction asset url too big: 33 > 32",
		},
		{
			acfg: AssetConfigTxnFields{
				AssetParams: basics.AssetParams{
					Decimals: 20,
				},
			},
			cv:            cv20,
			expectedError: "transaction asset decimals is too high (max is 19)",
		},
		{
			acfg: AssetConfigTxnFields{
				AssetParams: basics.AssetParams{
					URL: strings.Repeat("D", 97),
				},
			},
			cv:            cv28,
			expectedError: "transaction asset url too big: 97 > 96",
		},
	}

	for i, ac := range cases {
		name := fmt.Sprintf("acfg_i=%d", i)
		if ac.expectedError != "" {
			name = ac.expectedError
		}
		t.Run(name, func(t *testing.T) {
			cv := ac.cv
			if cv == "" {
				cv = protocol.ConsensusFuture
			}
			err := ac.acfg.wellFormed(config.Consensus[cv])
			if ac.expectedError != "" {
				require.ErrorContains(t, err, ac.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAfrzWellFormedErrors(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cases := []struct {
		afrz          AssetFreezeTxnFields
		expectedError string
	}{
		{
			afrz: AssetFreezeTxnFields{
				FreezeAccount: basics.Address{0x01},
				FreezeAsset:   0,
			},
			expectedError: "asset ID cannot be zero",
		},
		{
			afrz: AssetFreezeTxnFields{
				FreezeAccount: basics.Address{},
				FreezeAsset:   1,
			},
			expectedError: "freeze account cannot be empty",
		},
	}

	for i, ac := range cases {
		name := fmt.Sprintf("afrz_i=%d", i)
		if ac.expectedError != "" {
			name = ac.expectedError
		}
		t.Run(name, func(t *testing.T) {
			err := ac.afrz.wellFormed()
			if ac.expectedError != "" {
				require.ErrorContains(t, err, ac.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
