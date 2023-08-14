// Copyright (C) 2019-2023 Algorand, Inc.
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

package p2p

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/stretchr/testify/require"
)

func testP2PWithConfig(t *testing.T, cfgname string) {
	r := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", cfgname))
	defer fixture.ShutdownImpl(true) // preserve logs in testdir

	_, err := fixture.NC.AlgodClient()
	r.NoError(err)

	err = fixture.WaitForRound(10, 60*time.Second)
	r.NoError(err)
}

func TestP2PTwoNodes(t *testing.T) {
	testP2PWithConfig(t, "TwoNodes50EachP2P.json")
}

func TestP2PThreeNodesEvenDist(t *testing.T) {
	testP2PWithConfig(t, "ThreeNodesEvenDistP2P.json")
}

func TestP2PFiveNodes(t *testing.T) {
	testP2PWithConfig(t, "FiveNodesP2P.json")
}
