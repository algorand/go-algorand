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
	"github.com/algorand/go-algorand/protocol"
)

type loadedAccountDataEntry struct {
	address *basics.Address
	data    *ledgercore.AccountData
}

type loadedResourcesEntry struct {
	resource       *ledgercore.AccountResource
	address        *basics.Address
	creatableIndex basics.CreatableIndex
	creatableType  basics.CreatableType
}

// loadedTransactionGroup is a helper struct to allow asynchronous loading of the account data needed by the transaction groups
type loadedTransactionGroup struct {
	// group is the transaction group
	group []transactions.SignedTxnWithAD

	// accounts is a list of all the accounts balance records that the transaction group refer to and are needed.
	accounts []loadedAccountDataEntry

	// the following four are the resources used by the account
	resources []loadedResourcesEntry

	// err indicates whether any of the balances in this structure have failed to load. In case of an error, at least
	// one of the entries in the balances would be uninitialized.
	err error
}

// loadAccounts loads the account data for the provided transaction group list. It also loads the feeSink account and add it to the first returned transaction group.
// The order of the transaction groups returned by the channel is identical to the one in the input array.
func loadAccounts(ctx context.Context, l LedgerForEvaluator, rnd basics.Round, groups [][]transactions.SignedTxnWithAD, feeSinkAddr basics.Address, consensusParams config.ConsensusParams) chan loadedTransactionGroup {
	outChan := make(chan loadedTransactionGroup, len(groups))
	go loadAccountsInner(ctx, l, rnd, groups, feeSinkAddr, consensusParams, outChan)
	return outChan
}

// Return the maximum number of addresses referenced in any given transaction.
func maxAddressesInTxn(proto *config.ConsensusParams) int {
	return 7 + proto.MaxAppTxnAccounts
}

// groupTask helps to organize the account loading for each transaction group.
type groupTask struct {
	// balances contains the loaded balances each transaction group have
	balances []loadedAccountDataEntry
	// balancesCount is the number of balances that nees to be loaded per transaction group
	balancesCount int
	// resources contains the loaded resoruces each of the transaction groups have
	resources []loadedResourcesEntry
	// resourcesCount is the number of resources that nees to be loaded per transaction group
	resourcesCount int
	// done is a waiting channel for all the account data for the transaction group to be loaded
	done chan error
}

// preloaderTask manage the loading of a single element, whether it's a resource or an account address.
type preloaderTask struct {
	// account address to fetch
	address *basics.Address
	// resource id
	creatableIndex basics.CreatableIndex
	// resource type
	creatableType basics.CreatableType
	// a list of transaction group tasks that depends on this address
	groups []*groupTask
	// a list of indices into the groupTask.balances or groupTask.resources where the address would be stored
	groupIndices []int
}

type accountCreatableKey struct {
	address basics.Address
	cidx    basics.CreatableIndex
}

func loadAccountsAddAccountTask(addr *basics.Address, wg *groupTask, accountTasks map[basics.Address]*preloaderTask, addressesCh chan *preloaderTask) {
	if task, have := accountTasks[*addr]; !have {
		task := &preloaderTask{
			address:      addr,
			groups:       make([]*groupTask, 1, 4),
			groupIndices: make([]int, 1, 4),
		}
		task.groups[0] = wg
		task.groupIndices[0] = wg.balancesCount

		accountTasks[*addr] = task
		addressesCh <- task
	} else {
		task.groups = append(task.groups, wg)
		task.groupIndices = append(task.groupIndices, wg.balancesCount)
	}
	wg.balancesCount++
	return
}

func loadAccountsAddResourceTask(addr *basics.Address, cidx basics.CreatableIndex, ctype basics.CreatableType, wg *groupTask, resourceTasks map[accountCreatableKey]*preloaderTask, addressesCh chan *preloaderTask) {
	key := accountCreatableKey{
		cidx: cidx,
	}
	if addr != nil {
		key.address = *addr
	}
	if task, have := resourceTasks[key]; !have {
		task := &preloaderTask{
			address:        addr,
			groups:         make([]*groupTask, 1, 4),
			groupIndices:   make([]int, 1, 4),
			creatableIndex: cidx,
			creatableType:  ctype,
		}
		task.groups[0] = wg
		task.groupIndices[0] = wg.resourcesCount

		resourceTasks[key] = task
		addressesCh <- task
	} else {
		task.groups = append(task.groups, wg)
		task.groupIndices = append(task.groupIndices, wg.resourcesCount)
	}
	wg.resourcesCount++
	return
}

func loadAccountsInner(ctx context.Context, l LedgerForEvaluator, rnd basics.Round, groups [][]transactions.SignedTxnWithAD, feeSinkAddr basics.Address, consensusParams config.ConsensusParams, outChan chan loadedTransactionGroup) {
	defer close(outChan)

	accountTasks := make(map[basics.Address]*preloaderTask)
	resourceTasks := make(map[accountCreatableKey]*preloaderTask)
	addressesCh := make(chan *preloaderTask, len(groups)*consensusParams.MaxTxGroupSize*maxAddressesInTxn(&consensusParams))
	// totalBalances counts the total number of balances over all the transaction groups
	totalBalances := 0
	totalResources := 0

	// add the fee sink address to the accountTasks/addressesCh so that it will be loaded first.
	if len(groups) > 0 {
		task := &preloaderTask{
			address: &feeSinkAddr,
		}
		addressesCh <- task
		accountTasks[feeSinkAddr] = task
	}

	// iterate over the transaction groups and add all their account addresses to the list
	groupsReady := make([]groupTask, len(groups))
	for i := range groups {
		task := &groupsReady[i]
		for j := range groups[i] {
			stxn := &groups[i][j]
			switch stxn.Txn.Type {
			case protocol.PaymentTx:
				if !stxn.Txn.Receiver.IsZero() {
					loadAccountsAddAccountTask(&stxn.Txn.Receiver, task, accountTasks, addressesCh)
				}
				if !stxn.Txn.CloseRemainderTo.IsZero() {
					loadAccountsAddAccountTask(&stxn.Txn.CloseRemainderTo, task, accountTasks, addressesCh)
				}
			case protocol.AssetConfigTx:
				if stxn.Txn.ConfigAsset != 0 {
					loadAccountsAddResourceTask(nil, basics.CreatableIndex(stxn.Txn.ConfigAsset), basics.AssetCreatable, task, resourceTasks, addressesCh)
				}
			case protocol.AssetTransferTx:
				if !stxn.Txn.AssetSender.IsZero() {
					if stxn.Txn.XferAsset != 0 {
						loadAccountsAddResourceTask(&stxn.Txn.AssetSender, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, addressesCh)
					}
					loadAccountsAddAccountTask(&stxn.Txn.AssetSender, task, accountTasks, addressesCh)
				}
				if !stxn.Txn.AssetReceiver.IsZero() {
					if stxn.Txn.XferAsset != 0 {
						loadAccountsAddResourceTask(&stxn.Txn.AssetReceiver, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, addressesCh)
					}
					loadAccountsAddAccountTask(&stxn.Txn.AssetReceiver, task, accountTasks, addressesCh)
				}
				if !stxn.Txn.AssetCloseTo.IsZero() {
					if stxn.Txn.XferAsset != 0 {
						loadAccountsAddResourceTask(&stxn.Txn.AssetCloseTo, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, addressesCh)
					}
					loadAccountsAddAccountTask(&stxn.Txn.AssetCloseTo, task, accountTasks, addressesCh)
				}
			case protocol.AssetFreezeTx:
				if !stxn.Txn.FreezeAccount.IsZero() {
					if stxn.Txn.XferAsset != 0 {
						loadAccountsAddResourceTask(&stxn.Txn.FreezeAccount, basics.CreatableIndex(stxn.Txn.FreezeAsset), basics.AssetCreatable, task, resourceTasks, addressesCh)
					}
					loadAccountsAddAccountTask(&stxn.Txn.FreezeAccount, task, accountTasks, addressesCh)
				}
			case protocol.ApplicationCallTx:
				if stxn.Txn.ApplicationID != 0 {
					// load the global - so that we'll have the program
					loadAccountsAddResourceTask(nil, basics.CreatableIndex(stxn.Txn.ApplicationID), basics.AppCreatable, task, resourceTasks, addressesCh)
					// load the local - so that we'll have the local state
					loadAccountsAddResourceTask(&stxn.Txn.Sender, basics.CreatableIndex(stxn.Txn.ApplicationID), basics.AppCreatable, task, resourceTasks, addressesCh)
				}
				for _, fa := range stxn.Txn.ForeignApps {
					loadAccountsAddResourceTask(nil, basics.CreatableIndex(fa), basics.AppCreatable, task, resourceTasks, addressesCh)
				}
				for _, fa := range stxn.Txn.ForeignAssets {
					loadAccountsAddResourceTask(nil, basics.CreatableIndex(fa), basics.AssetCreatable, task, resourceTasks, addressesCh)
				}
				for ixa := range stxn.Txn.Accounts {
					if !stxn.Txn.Accounts[ixa].IsZero() {
						loadAccountsAddAccountTask(&stxn.Txn.Accounts[ixa], task, accountTasks, addressesCh)
					}
				}
			case protocol.CompactCertTx:
				fallthrough
			case protocol.KeyRegistrationTx:
				fallthrough
			default:
			}
			// If you add new addresses here, also add them in getTxnAddresses().
			if !stxn.Txn.Sender.IsZero() {
				loadAccountsAddAccountTask(&stxn.Txn.Sender, task, accountTasks, addressesCh)
			}
		}
		totalBalances += task.balancesCount
		totalResources += task.resourcesCount
	}

	// Add fee sink to the first group
	if len(groupsReady) > 0 {
		// the feeSinkAddr is known to be non-empty, so we don't need to test for that.
		loadAccountsAddAccountTask(&feeSinkAddr, &groupsReady[0], accountTasks, addressesCh)
		totalBalances++
	}
	close(addressesCh)

	// updata all the groups task :
	// allocate the correct number of balances, as well as
	// enough space on the "done" channel.
	allBalances := make([]loadedAccountDataEntry, totalBalances)
	allResources := make([]loadedResourcesEntry, totalResources)
	usedBalances := 0
	usedResources := 0
	for grpIdx := range groupsReady {
		gr := &groupsReady[grpIdx]
		gr.balances = allBalances[usedBalances : usedBalances+gr.balancesCount]
		if gr.resourcesCount > 0 {
			gr.resources = allResources[usedResources : usedResources+gr.resourcesCount]
			usedResources += gr.resourcesCount
		}
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
					if task.creatableIndex == 0 {
						// lookup the account data directly from the ledger.
						acctData, _, err := l.LookupWithoutRewards(rnd, *task.address)
						br := loadedAccountDataEntry{
							address: task.address,
							data:    &acctData,
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
					} else {
						if task.address == nil {
							// start off by figuring out the creator in case it's a global resource.
							creator, ok, err := l.GetCreatorForRound(rnd, task.creatableIndex, task.creatableType)
							if err != nil {
								// there was an error loading that entry.
								for _, wg := range task.groups {
									// notify the channel of the error.
									wg.done <- err
								}
								continue
							}
							if !ok {
								re := loadedResourcesEntry{
									creatableIndex: task.creatableIndex,
									creatableType:  task.creatableType,
								}
								// update all the group tasks with the new acquired balance.
								for i, wg := range task.groups {
									wg.resources[task.groupIndices[i]] = re
									// write a nil to indicate that we're loaded one entry.
									wg.done <- nil
								}
								continue
							}
							task.address = &creator
						}
						resource, err := l.LookupResource(rnd, *task.address, task.creatableIndex, task.creatableType)
						if err != nil {
							// there was an error loading that entry.
							for _, wg := range task.groups {
								// notify the channel of the error.
								wg.done <- err
							}
							continue
						}
						re := loadedResourcesEntry{
							resource:       &resource,
							address:        task.address,
							creatableIndex: task.creatableIndex,
							creatableType:  task.creatableType,
						}
						// update all the group tasks with the new acquired balance.
						for i, wg := range task.groups {
							wg.resources[task.groupIndices[i]] = re
							// write a nil to indicate that we're loaded one entry.
							wg.done <- nil
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
			group:     groups[i],
			accounts:  wg.balances,
			resources: wg.resources,
		}
	}
}
