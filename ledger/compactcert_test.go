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
	"github.com/algorand/go-algorand/protocol"
)

func TestValidateCompactCert(t *testing.T) {
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

	// TODO: a case that actually passes with no err?
}

// TODO: coverage of cases in AcceptableCompactCertWeight()
func TestAcceptableCompactCertWeight(t *testing.T) {
	var votersHdr bookkeeping.BlockHeader
	var firstValid basics.Round

	votersHdr.CurrentProtocol = "TestAcceptableCompactCertWeight"
	proto := config.Consensus[votersHdr.CurrentProtocol]
	proto.CompactCertRounds = 2
	config.Consensus[votersHdr.CurrentProtocol] = proto
	out := AcceptableCompactCertWeight(votersHdr, firstValid)
	require.Equal(t, uint64(0), out)
}

// TODO: coverage of cases in CompactCertParams()
