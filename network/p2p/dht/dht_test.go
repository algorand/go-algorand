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

package dht

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

func TestDHTBasic(t *testing.T) {
	h, err := libp2p.New()
	require.NoError(t, err)
	dht, err := MakeDHT(context.Background(), h, "devtestnet", []*peer.AddrInfo{})
	require.NoError(t, err)
	_, err = MakeDiscovery(dht)
	require.NoError(t, err)
	err = dht.Bootstrap(context.Background())
	require.NoError(t, err)
}

func TestTopicCid(t *testing.T) {
	/*
		topicMultihash, err := multihash.Sum([]byte(topic), multihash.SHA2_256, -1)
		topicCid := cid.NewCidV1(cid.Raw, topicMultihash)
		require.NoError(t, err)
		dht1Providers, err := dht1.FindProviders(context.TODO(), topicCid)
		require.NoError(t, err)
	*/
}
