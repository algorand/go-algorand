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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
   "github.com/algorand/go-algorand/testPartitioning"
)

func TestValidateCompactCert(t *testing.T) {
   testPartitioning.PartitionTest(t)

	var certHdr bookkeeping.BlockHeader
	var cert compactcert.Cert
	var votersHdr bookkeeping.BlockHeader
	var nextCertRnd basics.Round
	var atRound basics.Round

	// will definitely fail with nothing set up
	err := validateCompactCert(certHdr, cert, votersHdr, nextCertRnd, atRound)
	t.Log(err)
	require.NotNil(t, err)

	certHdr.CurrentProtocol = "TestValidateCompactCert"
	certHdr.Round = 1
	proto := config.Consensus[certHdr.CurrentProtocol]
	proto.CompactCertRounds = 2
	config.Consensus[certHdr.CurrentProtocol] = proto

	err = validateCompactCert(certHdr, cert, votersHdr, nextCertRnd, atRound)
	// still err, but a different err case to cover
	t.Log(err)
	require.NotNil(t, err)

	certHdr.Round = 4
	votersHdr.Round = 4
	err = validateCompactCert(certHdr, cert, votersHdr, nextCertRnd, atRound)
	// still err, but a different err case to cover
	t.Log(err)
	require.NotNil(t, err)

	votersHdr.Round = 2
	err = validateCompactCert(certHdr, cert, votersHdr, nextCertRnd, atRound)
	// still err, but a different err case to cover
	t.Log(err)
	require.NotNil(t, err)

	nextCertRnd = 4
	err = validateCompactCert(certHdr, cert, votersHdr, nextCertRnd, atRound)
	// still err, but a different err case to cover
	t.Log(err)
	require.NotNil(t, err)

	votersHdr.CurrentProtocol = certHdr.CurrentProtocol
	err = validateCompactCert(certHdr, cert, votersHdr, nextCertRnd, atRound)
	// still err, but a different err case to cover
	t.Log(err)
	require.NotNil(t, err)

	votersHdr.CompactCert = make(map[protocol.CompactCertType]bookkeeping.CompactCertState)
	cc := votersHdr.CompactCert[protocol.CompactCertBasic]
	cc.CompactCertVotersTotal.Raw = 100
	votersHdr.CompactCert[protocol.CompactCertBasic] = cc
	err = validateCompactCert(certHdr, cert, votersHdr, nextCertRnd, atRound)
	// still err, but a different err case to cover
	t.Log(err)
	require.NotNil(t, err)

	cert.SignedWeight = 101
	err = validateCompactCert(certHdr, cert, votersHdr, nextCertRnd, atRound)
	// still err, but a different err case to cover
	t.Log(err)
	require.NotNil(t, err)

	// Above cases leave validateCompactCert() with 100% coverage.
	// crypto/compactcert.Verify has its own tests
}

func TestAcceptableCompactCertWeight(t *testing.T) {
   testPartitioning.PartitionTest(t)

	var votersHdr bookkeeping.BlockHeader
	var firstValid basics.Round
	logger := logging.TestingLog(t)

	votersHdr.CurrentProtocol = "TestAcceptableCompactCertWeight"
	proto := config.Consensus[votersHdr.CurrentProtocol]
	proto.CompactCertRounds = 2
	config.Consensus[votersHdr.CurrentProtocol] = proto
	out := AcceptableCompactCertWeight(votersHdr, firstValid, logger)
	require.Equal(t, uint64(0), out)

	votersHdr.CompactCert = make(map[protocol.CompactCertType]bookkeeping.CompactCertState)
	cc := votersHdr.CompactCert[protocol.CompactCertBasic]
	cc.CompactCertVotersTotal.Raw = 100
	votersHdr.CompactCert[protocol.CompactCertBasic] = cc
	out = AcceptableCompactCertWeight(votersHdr, firstValid, logger)
	require.Equal(t, uint64(100), out)

	// this should exercise the second return case
	firstValid = basics.Round(5)
	out = AcceptableCompactCertWeight(votersHdr, firstValid, logger)
	require.Equal(t, uint64(100), out)

	firstValid = basics.Round(6)
	proto.CompactCertWeightThreshold = 999999999
	config.Consensus[votersHdr.CurrentProtocol] = proto
	out = AcceptableCompactCertWeight(votersHdr, firstValid, logger)
	require.Equal(t, uint64(0x17), out)

	proto.CompactCertRounds = 10000
	votersHdr.Round = 10000
	firstValid = basics.Round(29000)
	config.Consensus[votersHdr.CurrentProtocol] = proto
	cc.CompactCertVotersTotal.Raw = 0x7fffffffffffffff
	votersHdr.CompactCert[protocol.CompactCertBasic] = cc
	proto.CompactCertWeightThreshold = 0x7fffffff
	config.Consensus[votersHdr.CurrentProtocol] = proto
	out = AcceptableCompactCertWeight(votersHdr, firstValid, logger)
	require.Equal(t, uint64(0x4cd35a85213a92a2), out)

	// Covers everything except "overflow that shouldn't happen" branches
}

func TestCompactCertParams(t *testing.T) {
   testPartitioning.PartitionTest(t)

	var votersHdr bookkeeping.BlockHeader
	var hdr bookkeeping.BlockHeader

	res, err := CompactCertParams(votersHdr, hdr)
	require.Error(t, err) // not enabled

	votersHdr.CurrentProtocol = "TestCompactCertParams"
	proto := config.Consensus[votersHdr.CurrentProtocol]
	proto.CompactCertRounds = 2
	config.Consensus[votersHdr.CurrentProtocol] = proto
	votersHdr.Round = 1
	res, err = CompactCertParams(votersHdr, hdr)
	require.Error(t, err) // wrong round

	votersHdr.Round = 2
	hdr.Round = 3
	res, err = CompactCertParams(votersHdr, hdr)
	require.Error(t, err) // wrong round

	hdr.Round = 4
	res, err = CompactCertParams(votersHdr, hdr)
	require.Equal(t, hdr.Round+1, res.SigRound)

	// Covers all cases except overflow
}
