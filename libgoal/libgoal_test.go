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

package libgoal

import (
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestValidRounds(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	var firstValid, lastValid, validRounds, lastRound basics.Round

	lastRound = 1
	const maxTxnLife = 1000

	firstValid = 0
	lastValid = 0
	validRounds = 0
	fv, lv, err := computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.Equal(lastRound, fv)
	a.Equal(fv+maxTxnLife, lv)

	firstValid = 0
	lastValid = 0
	validRounds = maxTxnLife + 1
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.Equal(lastRound, fv)
	a.Equal(fv+maxTxnLife, lv)

	firstValid = 0
	lastValid = 0
	validRounds = maxTxnLife + 2
	_, _, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.Error(err)
	a.Equal("cannot construct transaction: txn validity period 1001 is greater than protocol max txn lifetime 1000", err.Error())

	firstValid = 0
	lastValid = 1
	validRounds = 2
	_, _, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.Error(err)
	a.Equal("cannot construct transaction: ambiguous input: lastValid = 1, validRounds = 2", err.Error())

	firstValid = 2
	lastValid = 1
	validRounds = 0
	_, _, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.Error(err)
	a.Equal("cannot construct transaction: txn would first be valid on round 2 which is after last valid round 1", err.Error())

	firstValid = 1
	lastValid = maxTxnLife + 2
	validRounds = 0
	_, _, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.Error(err)
	a.Equal("cannot construct transaction: txn validity period ( 1 to 1002 ) is greater than protocol max txn lifetime 1000", err.Error())

	firstValid = 1
	lastValid = maxTxnLife + 1
	validRounds = 0
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.EqualValues(1, fv)
	a.EqualValues(maxTxnLife+1, lv)

	firstValid = 0
	lastValid = lastRound + 1
	validRounds = 0
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.Equal(lastRound, fv)
	a.Equal(lastRound+1, lv)

	firstValid = 0
	lastValid = 0
	validRounds = 1
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.Equal(lastRound, fv)
	a.Equal(lastRound, lv)

	firstValid = 0
	lastValid = 0
	validRounds = maxTxnLife
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.Equal(lastRound, fv)
	a.Equal(lastRound+maxTxnLife-1, lv)

	firstValid = 1
	lastValid = 0
	validRounds = 1
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.EqualValues(1, fv)
	a.EqualValues(1, lv)

	firstValid = 1
	lastValid = 1
	validRounds = 0
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.EqualValues(1, fv)
	a.EqualValues(1, lv)

	firstValid = 100
	lastValid = 0
	validRounds = maxTxnLife
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.EqualValues(100, fv)
	a.EqualValues(100+maxTxnLife-1, lv)

	firstValid = 100
	lastValid = maxTxnLife
	validRounds = 0
	fv, lv, err = computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife)
	a.NoError(err)
	a.EqualValues(100, fv)
	a.EqualValues(maxTxnLife, lv)
}
