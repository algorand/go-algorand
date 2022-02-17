// Copyright (C) 2019-2022 Algorand, Inc.
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

package internal

import (
	"context"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// groupTask helps to organize the account loading for each transaction group.
type groupTask struct {
	// balances contains the loaded balances each transaction group have
	balances []ledgercore.NewBalanceRecord
	// balancesCount is the number of balances that nees to be loaded per transaction group
	balancesCount int
	// done is a waiting channel for all the account data for the transaction group to be loaded
	done chan error
}

// addrTask manage the loading of a single account address.
type addrTask struct {
	// account address to fetch
	address basics.Address
	// a list of transaction group tasks that depends on this address
	groups []*groupTask
	// a list of indices into the groupTask.balances where the address would be stored
	groupIndices []int
}

func initAccount(addr basics.Address, wg *groupTask, accountTasks map[basics.Address]*addrTask, addressesCh chan *addrTask) int {
	if addr.IsZero() {
		return 0
	}
	if task, have := accountTasks[addr]; !have {
		task := &addrTask{
			address:      addr,
			groups:       make([]*groupTask, 1, 4),
			groupIndices: make([]int, 1, 4),
		}
		task.groups[0] = wg
		task.groupIndices[0] = wg.balancesCount

		accountTasks[addr] = task
		addressesCh <- task
	} else {
		task.groups = append(task.groups, wg)
		task.groupIndices = append(task.groupIndices, wg.balancesCount)
	}
	wg.balancesCount++
	return 1
}

// loadAccounts loads the account data for the provided transaction group list. It also loads the feeSink account and add it to the first returned transaction group.
// The order of the transaction groups returned by the channel is identical to the one in the input array.
func loadAccounts(ctx context.Context, l LedgerForEvaluator, rnd basics.Round, groups [][]transactions.SignedTxnWithAD, feeSinkAddr basics.Address, consensusParams config.ConsensusParams) chan loadedTransactionGroup {
	outChan := make(chan loadedTransactionGroup, len(groups))
	go func() {
		defer close(outChan)

		accountTasks := make(map[basics.Address]*addrTask)
		addressesCh := make(chan *addrTask, len(groups)*consensusParams.MaxTxGroupSize*maxAddressesInTxn(&consensusParams))
		// totalBalances counts the total number of balances over all the transaction groups
		totalBalances := 0

		// add the fee sink address to the accountTasks/addressesCh so that it will be loaded first.
		if len(groups) > 0 {
			task := &addrTask{
				address: feeSinkAddr,
			}
			addressesCh <- task
			accountTasks[feeSinkAddr] = task
		}

		// iterate over the transaction groups and add all their account addresses to the list
		groupsReady := make([]*groupTask, len(groups))
		for i, group := range groups {
			task := &groupTask{}
			groupsReady[i] = task
			for _, stxn := range group {
				// If you add new addresses here, also add them in getTxnAddresses().
				totalBalances += initAccount(stxn.Txn.Sender, task, accountTasks, addressesCh)
				totalBalances += initAccount(stxn.Txn.Receiver, task, accountTasks, addressesCh)
				totalBalances += initAccount(stxn.Txn.CloseRemainderTo, task, accountTasks, addressesCh)
				totalBalances += initAccount(stxn.Txn.AssetSender, task, accountTasks, addressesCh)
				totalBalances += initAccount(stxn.Txn.AssetReceiver, task, accountTasks, addressesCh)
				totalBalances += initAccount(stxn.Txn.AssetCloseTo, task, accountTasks, addressesCh)
				totalBalances += initAccount(stxn.Txn.FreezeAccount, task, accountTasks, addressesCh)
				for _, xa := range stxn.Txn.Accounts {
					totalBalances += initAccount(xa, task, accountTasks, addressesCh)
				}
			}
		}

		// Add fee sink to the first group
		if len(groupsReady) > 0 {
			totalBalances += initAccount(feeSinkAddr, groupsReady[0], accountTasks, addressesCh)
		}
		close(addressesCh)

		// updata all the groups task :
		// allocate the correct number of balances, as well as
		// enough space on the "done" channel.
		allBalances := make([]ledgercore.NewBalanceRecord, totalBalances)
		usedBalances := 0
		for _, gr := range groupsReady {
			gr.balances = allBalances[usedBalances : usedBalances+gr.balancesCount]
			gr.done = make(chan error, gr.balancesCount)
			usedBalances += gr.balancesCount
		}

		// create few go-routines to load asyncroniously the account data.
		for i := 0; i < asyncAccountLoadingThreadCount; i++ {
			go func() {
				for {
					select {
					case task, ok := <-addressesCh:
						// load the address
						if !ok {
							// the channel got closed, which mean we're done.
							return
						}
						// lookup the account data directly from the ledger.
						acctData, _, err := l.LookupWithoutRewards(rnd, task.address)
						br := ledgercore.NewBalanceRecord{
							Addr:        task.address,
							AccountData: acctData,
						}
						// if there is no error..
						if err == nil {
							// update all the group tasks with the new acquired balance.
							for i, wg := range task.groups {
								wg.balances[task.groupIndices[i]] = br
								// write a nil to indicate that we're loaded one entry.
								wg.done <- nil
							}
						} else {
							// there was an error loading that entry.
							for _, wg := range task.groups {
								// notify the channel of the error.
								wg.done <- err
							}
						}
					case <-ctx.Done():
						// if the context was canceled, abort right away.
						return
					}

				}
			}()
		}

		// iterate on the transaction groups tasks. This array retains the original order.
		for i, wg := range groupsReady {
			// Wait to receive wg.balancesCount nil error messages, one for each address referenced in this txn group.
			for j := 0; j < wg.balancesCount; j++ {
				select {
				case err := <-wg.done:
					if err != nil {
						// if there is an error, report the error to the output channel.
						outChan <- loadedTransactionGroup{
							group: groups[i],
							err:   err,
						}
						return
					}
				case <-ctx.Done():
					return
				}
			}
			// if we had no error, write the result to the output channel.
			// this write will not block since we preallocated enough space on the channel.
			outChan <- loadedTransactionGroup{
				group:    groups[i],
				balances: wg.balances,
			}
		}
	}()
	return outChan
}
