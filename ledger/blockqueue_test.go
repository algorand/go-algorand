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

package ledger

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

func TestPutBlockTooOld(t *testing.T) {
	genesisInitState, _, _ := genesis(10)

	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(logging.Base(), dbName, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	blk := bookkeeping.Block{}
	var cert agreement.Certificate
	err = l.blockQ.putBlock(blk, cert)

	expectedErr := &ledgercore.BlockInLedgerError{}
	require.True(t, errors.As(err, expectedErr))
}

func TestGetEncodedBlockCert(t *testing.T) {
	genesisInitState, _, _ := genesis(10)

	const inMem = true
	cfg := config.GetDefaultLocal()
	l, err := OpenLedger(logging.Base(), t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err)
	defer l.Close()

	blk := bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{Round: 1}}
	cert := agreement.Certificate{Round: 1}
	err = l.blockQ.putBlock(blk, cert)
	require.NoError(t, err)

	var blkBytes []byte
	var certBytes []byte

	blkBytes, certBytes, err = l.blockQ.getEncodedBlockCert(0)
	require.Equal(t, protocol.Encode(&genesisInitState.Block), blkBytes)
	require.Equal(t, protocol.Encode(&agreement.Certificate{}), certBytes)
	require.NoError(t, err)

	blkBytes, certBytes, err = l.blockQ.getEncodedBlockCert(1)
	require.Equal(t, protocol.Encode(&blk), blkBytes)
	require.Equal(t, protocol.Encode(&cert), certBytes)
	require.NoError(t, err)

	_, _, err = l.blockQ.getEncodedBlockCert(100) // should not be entry for this round

	expectedErr := &ledgercore.ErrNoEntry{}
	require.True(t, errors.As(err, expectedErr))
}
