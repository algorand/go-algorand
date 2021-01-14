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

package goal

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClerkSendNoteEncoding(t *testing.T) {
	defer fixture.SetTestContext(t)()
	a := require.New(t)

	// wait for consensus on first round prior to sending transactions, time out after 2 minutes
	err := fixture.WaitForRound(2, 2*time.Minute)
	a.NoError(err)

	// Send txn to 2nd account with a Note.
	// Wait for Txn to be committed.
	// Read Txn and verify note matches.

	accounts, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	a.NotEmpty(accounts)
	account := accounts[0].Address

	const noteText = "Sample Text-based Note"
	txID, err := fixture.ClerkSend(account, account, 100, 1, noteText)
	a.NoError(err)
	a.NotEmpty(txID)

	// Send 2nd txn using the note encoded as base-64 (using --noteb64)
	originalNoteb64Text := "Noteb64-encoded text With Binary \u0001x1x0x3"
	noteb64 := base64.StdEncoding.EncodeToString([]byte(originalNoteb64Text))
	txID2, err := fixture.ClerkSendNoteb64(account, account, 100, 1, noteb64)
	a.NoError(err)
	a.NotEmpty(txID2)

	client := fixture.LibGoalClient
	status, err := client.Status()
	a.NoError(err)

	var foundTx1, foundTx2 bool
	const maxRetry = 10

	for i := uint64(0); i < maxRetry && (!foundTx1 || !foundTx2); i++ {
		if !foundTx1 {
			tx1, err := fixture.WaitForConfirmedTxn(status.LastRound+i, account, txID)
			if err == nil {
				foundTx1 = true
				a.Equal(noteText, string(tx1.Note))
			}
		}
		if !foundTx2 {
			tx2, err := fixture.WaitForConfirmedTxn(status.LastRound+i, account, txID2)
			if err == nil {
				foundTx2 = true
				// If the note matches our original text, then goal is still expecting strings encoded
				// with StdEncoding.EncodeToString() when using --noteb64 parameter
				a.Equal(originalNoteb64Text, string(tx2.Note), "goal should decode noteb64 with base64.StdEncoding")
			}
		}
	}

	a.True(foundTx1, "did not find transaction 1: %s", txID)
	a.True(foundTx2, "did not find transaction 2: %s", txID2)

}
