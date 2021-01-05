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

package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func TestInspect(t *testing.T) {
	var err error

	var empty transactions.SignedTxn
	_, err = inspectTxn(empty)
	require.NoError(t, err)

	var payment transactions.SignedTxn
	crypto.RandBytes(payment.Sig[:])
	payment.Txn.Type = protocol.PaymentTx
	crypto.RandBytes(payment.Txn.Sender[:])
	crypto.RandBytes(payment.Txn.Receiver[:])
	payment.Txn.Fee.Raw = crypto.RandUint64()
	payment.Txn.Amount.Raw = crypto.RandUint64()
	payment.Txn.FirstValid = basics.Round(crypto.RandUint64())
	payment.Txn.LastValid = basics.Round(crypto.RandUint64())
	_, err = inspectTxn(payment)
	require.NoError(t, err)

	var keyreg transactions.SignedTxn
	crypto.RandBytes(keyreg.Sig[:])
	keyreg.Txn.Type = protocol.KeyRegistrationTx
	crypto.RandBytes(keyreg.Txn.Sender[:])
	keyreg.Txn.Fee.Raw = crypto.RandUint64()
	keyreg.Txn.FirstValid = basics.Round(crypto.RandUint64())
	keyreg.Txn.LastValid = basics.Round(crypto.RandUint64())
	crypto.RandBytes(keyreg.Txn.VotePK[:])
	crypto.RandBytes(keyreg.Txn.SelectionPK[:])
	_, err = inspectTxn(keyreg)
	require.NoError(t, err)

	var full transactions.SignedTxn
	crypto.RandBytes(full.Sig[:])
	full.Msig.Version = uint8(crypto.RandUint64())
	full.Msig.Threshold = uint8(crypto.RandUint64())
	full.Msig.Subsigs = make([]crypto.MultisigSubsig, 2)
	crypto.RandBytes(full.Msig.Subsigs[0].Key[:])
	crypto.RandBytes(full.Msig.Subsigs[0].Sig[:])
	crypto.RandBytes(full.Msig.Subsigs[1].Key[:])
	crypto.RandBytes(full.Msig.Subsigs[1].Sig[:])
	full.Txn.Type = protocol.UnknownTx
	crypto.RandBytes(full.Txn.Sender[:])
	full.Txn.Fee.Raw = crypto.RandUint64()
	full.Txn.FirstValid = basics.Round(crypto.RandUint64())
	full.Txn.LastValid = basics.Round(crypto.RandUint64())
	full.Txn.Note = make([]byte, 256)
	crypto.RandBytes(full.Txn.Note[:])
	full.Txn.GenesisID = "testid"
	crypto.RandBytes(full.Txn.GenesisHash[:])
	crypto.RandBytes(full.Txn.VotePK[:])
	crypto.RandBytes(full.Txn.SelectionPK[:])
	full.Txn.VoteFirst = basics.Round(crypto.RandUint64())
	full.Txn.VoteLast = basics.Round(crypto.RandUint64())
	full.Txn.VoteKeyDilution = crypto.RandUint64()
	full.Txn.Amount.Raw = crypto.RandUint64()
	crypto.RandBytes(full.Txn.Receiver[:])
	crypto.RandBytes(full.Txn.CloseRemainderTo[:])
	_, err = inspectTxn(full)
	require.NoError(t, err)
}
