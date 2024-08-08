// Copyright (C) 2019-2024 Algorand, Inc.
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

package network

import (
	"strings"
	"testing"

	"github.com/DataDog/zstd"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestZstdDecompress(t *testing.T) {
	partitiontest.PartitionTest(t)

	// happy case - small message
	msg := []byte(strings.Repeat("1", 2048))
	compressed, err := zstd.Compress(nil, msg)
	require.NoError(t, err)
	d := zstdProposalDecompressor{}
	decompressed, err := d.convert(compressed)
	require.NoError(t, err)
	require.Equal(t, msg, decompressed)

	// error case - large message
	msg = []byte(strings.Repeat("1", MaxDecompressedMessageSize+10))
	compressed, err = zstd.Compress(nil, msg)
	require.NoError(t, err)
	decompressed, err = d.convert(compressed)
	require.Error(t, err)
	require.Nil(t, decompressed)
}

func TestZstdCompressMsg(t *testing.T) {
	partitiontest.PartitionTest(t)

	ppt := len(protocol.ProposalPayloadTag)
	data := []byte("data")
	comp, msg := zstdCompressMsg([]byte(protocol.ProposalPayloadTag), data)
	require.Empty(t, msg)
	require.Equal(t, []byte(protocol.ProposalPayloadTag), comp[:ppt])
	require.Equal(t, zstdCompressionMagic[:], comp[ppt:ppt+len(zstdCompressionMagic)])
	d := zstdProposalDecompressor{}
	decompressed, err := d.convert(comp[ppt:])
	require.NoError(t, err)
	require.Equal(t, data, decompressed)
}

type converterTestLogger struct {
	logging.Logger
	WarnfCallback func(string, ...interface{})
	warnMsgCount  int
}

func (cl *converterTestLogger) Warnf(s string, args ...interface{}) {
	cl.warnMsgCount++
}

func TestWsPeerMsgDataConverterConvert(t *testing.T) {
	partitiontest.PartitionTest(t)

	c := wsPeerMsgDataConverter{}
	c.ppdec = zstdProposalDecompressor{}
	tag := protocol.AgreementVoteTag
	data := []byte("data")

	r, err := c.convert(tag, data)
	require.NoError(t, err)
	require.Equal(t, data, r)

	tag = protocol.ProposalPayloadTag
	l := converterTestLogger{}
	c.log = &l
	c.ppdec = zstdProposalDecompressor{}
	r, err = c.convert(tag, data)
	require.NoError(t, err)
	require.Equal(t, data, r)
	require.Equal(t, 1, l.warnMsgCount)

	l = converterTestLogger{}
	c.log = &l

	comp, err := zstd.Compress(nil, data)
	require.NoError(t, err)

	r, err = c.convert(tag, comp)
	require.NoError(t, err)
	require.Equal(t, data, r)
	require.Equal(t, 0, l.warnMsgCount)
}
