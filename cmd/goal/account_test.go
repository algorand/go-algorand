// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestIsPartkeyRegistered(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	key := model.AccountParticipation{
		SelectionParticipationKey: []byte{1, 2, 3},
		VoteParticipationKey:      []byte{4, 5, 6},
		VoteFirstValid:            10,
		VoteLastValid:             1000,
		VoteKeyDilution:           100,
	}
	part := model.ParticipationKey{Key: key}

	require.False(t, isPartkeyRegistered(model.Account{}, part))

	registered := key
	require.True(t, isPartkeyRegistered(model.Account{Participation: &registered}, part))

	mutations := map[string]func(p *model.AccountParticipation){
		"selection key": func(p *model.AccountParticipation) { p.SelectionParticipationKey = []byte{9} },
		"vote key":      func(p *model.AccountParticipation) { p.VoteParticipationKey = []byte{9} },
		"first valid":   func(p *model.AccountParticipation) { p.VoteFirstValid++ },
		"last valid":    func(p *model.AccountParticipation) { p.VoteLastValid++ },
		"key dilution":  func(p *model.AccountParticipation) { p.VoteKeyDilution++ },
	}
	for name, mutate := range mutations {
		other := key
		mutate(&other)
		require.False(t, isPartkeyRegistered(model.Account{Participation: &other}, part), name)
	}
}
