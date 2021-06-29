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

package kmdtest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/kmd/client"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/testpartitioning"
)

func TestServerStartsStopsSuccessfully(t *testing.T) {
	testpartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	f.Setup(t)
	defer f.Shutdown()

	// Test that `GET /versions` works
	req := kmdapi.VersionsRequest{}
	resp := kmdapi.VersionsResponse{}
	err := f.Client.DoV1Request(req, &resp)
	a.NoError(err)
}

func TestBadAuthFails(t *testing.T) {
	testpartitioning.PartitionTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))
	var f fixtures.KMDFixture
	f.Setup(t)
	defer f.Shutdown()

	// Make a client with a bad token
	badAPIToken := strings.Repeat("x", 64)
	client, err := client.MakeKMDClient(f.Sock, badAPIToken)
	a.NoError(err)

	// Test that `GET /v1/wallets` fails with the bad token
	req := kmdapi.APIV1GETWalletsRequest{}
	resp := kmdapi.APIV1GETWalletsResponse{}
	err = client.DoV1Request(req, &resp)
	a.Error(err)
}

func TestGoodAuthSucceeds(t *testing.T) {
	testpartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	t.Parallel()
	var f fixtures.KMDFixture
	f.Setup(t)
	defer f.Shutdown()

	// Test that `GET /v1/wallets` succeeds with the correct token. f.Client is
	// already initialized with the correct token in the test fixture
	req := kmdapi.APIV1GETWalletsRequest{}
	resp := kmdapi.APIV1GETWalletsResponse{}
	err := f.Client.DoV1Request(req, &resp)
	a.NoError(err)
}
