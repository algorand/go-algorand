// Copyright (C) 2019 Algorand, Inc.
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
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

var feeSink = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}

func TestKeyregApply(t *testing.T) {
	secretSrc := keypair()
	src := basics.Address(secretSrc.SignatureVerifier)
	vrfSecrets := crypto.GenerateVRFSecrets()
	secretParticipation := keypair()

	tx := Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: Header{
			Sender:     src,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		KeyregTxnFields: KeyregTxnFields{
			VotePK:      crypto.OneTimeSignatureVerifier(secretParticipation.SignatureVerifier),
			SelectionPK: vrfSecrets.PK,
		},
	}
	_, err := tx.Apply(mockBalances{protocol.ConsensusCurrentVersion}, SpecialAddresses{FeeSink: feeSink}, 0)
	require.NoError(t, err)

	tx.Sender = feeSink
	_, err = tx.Apply(mockBalances{protocol.ConsensusCurrentVersion}, SpecialAddresses{FeeSink: feeSink}, 0)
	require.Error(t, err)
}
