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

package node

import (
	"sort"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
)

const numTopAccounts = 20

type topAccountListener struct {
	log logging.Logger

	round basics.Round

	onlineCirculation basics.MicroAlgos

	totalCirculation basics.MicroAlgos

	// Cached between rounds to optimize ledger lookups.
	accounts []basics.AccountDetail
}

func makeTopAccountListener(log logging.Logger) topAccountListener {
	return topAccountListener{
		log: log,
		// TODO: If needed, increase size of this slice to buffer some accounts beyond the TopN.
		accounts: make([]basics.AccountDetail, 0, numTopAccounts),
	}
}

func (t *topAccountListener) init(balances basics.BalanceDetail) {
	t.round = balances.Round
	t.onlineCirculation = balances.OnlineMoney
	t.totalCirculation = balances.TotalMoney
	t.accounts = t.accounts[:0]

	// TODO: After ledger refactor this might be replaced with a loop processing pages of results from a SQL command.
	t.accounts = updateTopAccounts(t.accounts, balances.Accounts)
}

// BlockListener event, triggered when the ledger writes a new block.
func (t *topAccountListener) OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta) {
	// XXX revise for new ledger API
	// t.update(block, balances)

	// If number of accounts after update is insufficient, do a full re-init
	if len(t.accounts) < numTopAccounts {
		// XXX revise for new ledger API
		// t.init(balances)
	}

	t.sendEvent()
}

// Account cache update logic here.
func (t *topAccountListener) update(b bookkeeping.Block, balances basics.BalanceDetail) {
	lastRound := t.round

	// Update metadata.
	t.round = balances.Round
	t.onlineCirculation = balances.OnlineMoney
	t.totalCirculation = balances.TotalMoney

	// Invalidate accounts if a round is missed (this also causes the accounts to be lazily initialized).
	if lastRound+1 != balances.Round {
		t.accounts = t.accounts[:0]
		return
	}

	// No transactions to update.
	if len(balances.Accounts) == 0 {
		return
	}

	// Lookup map for updated accounts.
	accountSet := make(map[basics.Address]bool)

	payset, err := b.DecodePaysetFlat()
	if err != nil {
		return
	}

	for _, txad := range payset {
		tx := txad.SignedTxn
		if tx.Txn.Type == protocol.PaymentTx {
			accountSet[tx.Txn.Receiver] = true
			if tx.Txn.CloseRemainderTo != (basics.Address{}) {
				accountSet[tx.Txn.CloseRemainderTo] = true
			}
		}
		accountSet[tx.Txn.Src()] = true
	}

	// TODO: This loop may not be needed with the ledger refactor.
	// Since the balance list currently is unrelated to the transaction list, must iterate balances.
	for _, tx := range balances.Accounts {
		accountSet[tx.Address] = true
	}

	// Remove any accounts in the updated accountSet (they'll be merged back if necessary)
	t.accounts = removeSome(t.accounts, func(addr basics.AccountDetail) bool { return accountSet[addr.Address] })

	// Grab the smallest record after removing modified accounts
	smallestAccountSize := basics.MicroAlgos{Raw: 0}
	if len(t.accounts) != 0 {
		smallestAccountSize = t.accounts[len(t.accounts)-1].Algos
	}

	t.accounts = updateTopAccounts(t.accounts, balances.Accounts)

	// Truncate any accounts after the smallest balance.
	// This triggers a full re-init if the length falls below 'numTopAccounts'
	for i, acct := range t.accounts {
		if acct.Algos.LessThan(smallestAccountSize) {
			t.accounts = t.accounts[:i]
			return
		}
	}
}

// Helper method to defragment a slice using a predicate to identify stale entries.
func removeSome(slice []basics.AccountDetail, predicate func(basics.AccountDetail) bool) []basics.AccountDetail {
	// Remove updated accounts (they'll be merged back in as necessary)
	next, end := 0, 0
	for (next + end) < len(slice) {
		if predicate(slice[next+end]) {
			end++
		} else {
			slice[next] = slice[next+end]
			next++
		}
	}

	return slice[:next]
}

// Merge largest accounts from balances into topN, removing values from topN as necessary.
// The underlying capacity will not be modified, but the length may increase.
// Note: Doesn't check for duplicates.
func updateTopAccounts(topN []basics.AccountDetail, balances []basics.AccountDetail) []basics.AccountDetail {
	for _, account := range balances {
		balance := account.Algos

		// Quick check for topN if capacity is reached.
		if account.Status != basics.Online || len(topN) != 0 && len(topN) == cap(topN) && balance.Raw <= topN[len(topN)-1].Algos.Raw {
			continue
		}

		// Find insertion point.
		pos := sort.Search(len(topN), func(i int) bool {
			return topN[i].Algos.LessThan(balance)
		})

		// Increase capacity if more space is available.
		if len(topN) < cap(topN) {
			topN = topN[:len(topN)+1]
		}

		// Shift upper elements and insert
		if pos < len(topN) {
			copy(topN[pos+1:], topN[pos:])
			topN[pos] = account
		}
	}

	return topN
}

// Compile current top account state into a telemetry event, and send it.
func (t *topAccountListener) sendEvent() {
	// Build accounts object.
	payload := make([]map[string]interface{}, 0)
	fCirculation := float64(t.onlineCirculation.ToUint64())
	for _, account := range t.accounts[:] {
		entry := make(map[string]interface{})
		entry["address"] = account.Address.String()
		entry["balance"] = account.Algos.ToUint64()
		entry["stake"] = float64(account.Algos.ToUint64()) / fCirculation
		payload = append(payload, entry)
	}

	// Send it out
	t.log.EventWithDetails(telemetryspec.Accounts, telemetryspec.TopAccountsEvent,
		telemetryspec.TopAccountEventDetails{
			Round:              uint64(t.round),
			OnlineAccounts:     payload,
			OnlineCirculation:  t.onlineCirculation.ToUint64(),
			OfflineCirculation: t.totalCirculation.ToUint64() - t.onlineCirculation.ToUint64(),
		})
}
