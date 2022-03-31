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

package prefetcher

import (
	"context"
	"sync/atomic"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// asyncAccountLoadingThreadCount controls how many go routines would be used
// to load the account data before the Eval() start processing individual
// transaction group.
const asyncAccountLoadingThreadCount = 4

// Ledger is a ledger interfaces for prefetcher.
type Ledger interface {
	LookupWithoutRewards(basics.Round, basics.Address) (ledgercore.AccountData, basics.Round, error)
	LookupAsset(basics.Round, basics.Address, basics.AssetIndex) (ledgercore.AssetResource, error)
	LookupApplication(basics.Round, basics.Address, basics.AppIndex) (ledgercore.AppResource, error)
	GetCreatorForRound(basics.Round, basics.CreatableIndex, basics.CreatableType) (basics.Address, bool, error)
}

// LoadedAccountDataEntry describes a loaded account.
type LoadedAccountDataEntry struct {
	Address *basics.Address
	Data    *ledgercore.AccountData
}

// LoadedResourcesEntry describes a loaded resource.
type LoadedResourcesEntry struct {
	// Resource is the loaded Resource entry. unless address is nil, Resource would always contain a valid ledgercore.AccountResource pointer.
	Resource *ledgercore.AccountResource
	// Address might be empty if the resource does not exist. In that case creatableIndex and creatableType would still be valid while resource would be nil.
	Address        *basics.Address
	CreatableIndex basics.CreatableIndex
	CreatableType  basics.CreatableType
}

// LoadedTransactionGroup is a helper struct to allow asynchronous loading of the account data needed by the transaction groups
type LoadedTransactionGroup struct {
	// the transaction group
	TxnGroup []transactions.SignedTxnWithAD

	// Accounts is a list of all the Accounts balance records that the transaction group refer to and are needed.
	Accounts []LoadedAccountDataEntry

	// the following four are the Resources used by the account
	Resources []LoadedResourcesEntry

	// Err indicates whether any of the balances in this structure have failed to load. In case of an error, at least
	// one of the entries in the balances would be uninitialized.
	Err error
}

// accountPrefetcher used to prefetch accounts balances and resources before the evaluator is being called.
type accountPrefetcher struct {
	ledger          Ledger
	rnd             basics.Round
	groups          [][]transactions.SignedTxnWithAD
	feeSinkAddr     basics.Address
	consensusParams config.ConsensusParams
	outChan         chan LoadedTransactionGroup
}

// PrefetchAccounts loads the account data for the provided transaction group list. It also loads the feeSink account and add it to the first returned transaction group.
// The order of the transaction groups returned by the channel is identical to the one in the input array.
func PrefetchAccounts(ctx context.Context, l Ledger, rnd basics.Round, groups [][]transactions.SignedTxnWithAD, feeSinkAddr basics.Address, consensusParams config.ConsensusParams) <-chan LoadedTransactionGroup {
	prefetcher := &accountPrefetcher{
		ledger:          l,
		rnd:             rnd,
		groups:          groups,
		feeSinkAddr:     feeSinkAddr,
		consensusParams: consensusParams,
		outChan:         make(chan LoadedTransactionGroup, len(groups)),
	}

	go prefetcher.prefetch(ctx)
	return prefetcher.outChan
}

// groupTask helps to organize the account loading for each transaction group.
type groupTask struct {
	// incompleteCount is the number of resources+balances still pending and need to be loaded
	// this variable is used by as atomic variable to synchronize the readiness of the group taks.
	// in order to ensure support on 32-bit platforms, this variable need to be 64-bit aligned.
	incompleteCount int64
	// the group task index - aligns with the index of the transaction group in the
	// provided groups slice. The usage of int64 here is to made sure the size of the
	// structure is 64-bit aligned. If this not the case, then it would fail the atomic
	// operations on the incompleteCount on 32-bit systems.
	groupTaskIndex int64
	// balances contains the loaded balances each transaction group have
	balances []LoadedAccountDataEntry
	// balancesCount is the number of balances that nees to be loaded per transaction group
	balancesCount int
	// resources contains the loaded resources each of the transaction groups have
	resources []LoadedResourcesEntry
	// resourcesCount is the number of resources that nees to be loaded per transaction group
	resourcesCount int
}

// preloaderTask manage the loading of a single element, whether it's a resource or an account address.
type preloaderTask struct {
	// account address to fetch
	address *basics.Address
	// resource id
	creatableIndex basics.CreatableIndex
	// resource type
	creatableType basics.CreatableType
	// a list of transaction group tasks that depends on this address or resource
	groups []*groupTask
	// a list of indices into the groupTask.balances or groupTask.resources where the address would be stored
	groupIndices []int
}

// preloaderTaskQueue is a dynamic linked list of enqueued entries, optimized for non-syncronized insertion and
// syncronized extraction
type preloaderTaskQueue struct {
	next               *preloaderTaskQueue
	used               int
	entries            []*preloaderTask
	baseIdx            int
	maxTxnGroupEntries int
}

type groupTaskDone struct {
	groupIdx int64
	err      error
}

func allocPreloaderQueue(count int, maxTxnGroupEntries int) preloaderTaskQueue {
	return preloaderTaskQueue{
		entries:            make([]*preloaderTask, count*2+maxTxnGroupEntries*2),
		maxTxnGroupEntries: maxTxnGroupEntries,
	}
}

// enqueue places the queued entry on the queue, returning the latest queue
// ( in case the current "page" ran out of space )
func (pq *preloaderTaskQueue) enqueue(t *preloaderTask) {
	pq.entries[pq.used] = t
	pq.used++
}

func (pq *preloaderTaskQueue) expand() *preloaderTaskQueue {
	if cap(pq.entries)-pq.used < pq.maxTxnGroupEntries {
		pq.next = &preloaderTaskQueue{
			entries:            make([]*preloaderTask, cap(pq.entries)*2),
			used:               0,
			baseIdx:            pq.baseIdx + pq.used,
			maxTxnGroupEntries: pq.maxTxnGroupEntries,
		}
		return pq.next
	}
	return pq
}

func (pq *preloaderTaskQueue) getTaskAtIndex(idx int) (*preloaderTaskQueue, *preloaderTask) {
	localIdx := idx - pq.baseIdx
	if pq.used > localIdx {
		return pq, pq.entries[localIdx]
	}
	if pq.next != nil {
		return pq.next.getTaskAtIndex(idx)
	}
	return pq, nil
}

type accountCreatableKey struct {
	address basics.Address
	cidx    basics.CreatableIndex
}

func loadAccountsAddAccountTask(addr *basics.Address, wt *groupTask, accountTasks map[basics.Address]*preloaderTask, queue *preloaderTaskQueue) {
	if addr.IsZero() {
		return
	}
	if task, have := accountTasks[*addr]; !have {
		task := &preloaderTask{
			address:      addr,
			groups:       make([]*groupTask, 1, 4),
			groupIndices: make([]int, 1, 4),
		}
		task.groups[0] = wt
		task.groupIndices[0] = wt.balancesCount

		accountTasks[*addr] = task
		queue.enqueue(task)
	} else {
		task.groups = append(task.groups, wt)
		task.groupIndices = append(task.groupIndices, wt.balancesCount)
	}
	wt.balancesCount++
}

func loadAccountsAddResourceTask(addr *basics.Address, cidx basics.CreatableIndex, ctype basics.CreatableType, wt *groupTask, resourceTasks map[accountCreatableKey]*preloaderTask, queue *preloaderTaskQueue) {
	if cidx == 0 {
		return
	}
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
		task.groups[0] = wt
		task.groupIndices[0] = wt.resourcesCount

		resourceTasks[key] = task
		queue.enqueue(task)
	} else {
		task.groups = append(task.groups, wt)
		task.groupIndices = append(task.groupIndices, wt.resourcesCount)
	}
	wt.resourcesCount++
}

// prefetch would process the input transaction groups by analyzing each of the transaction groups and building
// an execution queue that would allow us to fetch all the dependencies for the input transaction groups in order
// and output these onto a channel.
func (p *accountPrefetcher) prefetch(ctx context.Context) {
	defer close(p.outChan)
	accountTasks := make(map[basics.Address]*preloaderTask)
	resourceTasks := make(map[accountCreatableKey]*preloaderTask)

	var maxTxnGroupEntries int
	if p.consensusParams.Application {
		// the extra two are for the sender account data, plus the application global state
		maxTxnGroupEntries = p.consensusParams.MaxTxGroupSize * (2 + p.consensusParams.MaxAppTxnAccounts + p.consensusParams.MaxAppTxnForeignApps + p.consensusParams.MaxAppTxnForeignAssets)
	} else {
		// 8 is the number of resources+account used in the AssetTransferTx, which is the largest one.
		maxTxnGroupEntries = p.consensusParams.MaxTxGroupSize * 8
	}

	tasksQueue := allocPreloaderQueue(len(p.groups), maxTxnGroupEntries)

	// totalBalances counts the total number of balances over all the transaction groups
	totalBalances := 0
	totalResources := 0

	groupsReady := make([]groupTask, len(p.groups))

	// Add fee sink to the first group
	if len(p.groups) > 0 {
		// the feeSinkAddr is known to be non-empty
		feeSinkPreloader := &preloaderTask{
			address:      &p.feeSinkAddr,
			groups:       []*groupTask{&groupsReady[0]},
			groupIndices: []int{0},
		}
		groupsReady[0].balancesCount = 1
		accountTasks[p.feeSinkAddr] = feeSinkPreloader
		tasksQueue.enqueue(feeSinkPreloader)
	}

	// iterate over the transaction groups and add all their account addresses to the list
	queue := &tasksQueue
	for i := range p.groups {
		task := &groupsReady[i]
		for j := range p.groups[i] {
			stxn := &p.groups[i][j]
			switch stxn.Txn.Type {
			case protocol.PaymentTx:
				loadAccountsAddAccountTask(&stxn.Txn.Receiver, task, accountTasks, queue)
				loadAccountsAddAccountTask(&stxn.Txn.CloseRemainderTo, task, accountTasks, queue)
			case protocol.AssetConfigTx:
				loadAccountsAddResourceTask(nil, basics.CreatableIndex(stxn.Txn.ConfigAsset), basics.AssetCreatable, task, resourceTasks, queue)
			case protocol.AssetTransferTx:
				if !stxn.Txn.AssetSender.IsZero() {
					loadAccountsAddResourceTask(nil, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, queue)
					loadAccountsAddResourceTask(&stxn.Txn.AssetSender, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, queue)
				} else {
					loadAccountsAddResourceTask(&stxn.Txn.Sender, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, queue)
					if stxn.Txn.AssetAmount == 0 && (stxn.Txn.AssetReceiver == stxn.Txn.Sender) {
						// opt in
						loadAccountsAddResourceTask(nil, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, queue)
					}
				}
				if !stxn.Txn.AssetReceiver.IsZero() {
					loadAccountsAddResourceTask(&stxn.Txn.AssetReceiver, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, queue)
				}
				if !stxn.Txn.AssetCloseTo.IsZero() {
					loadAccountsAddResourceTask(&stxn.Txn.AssetCloseTo, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, queue)
				}
			case protocol.AssetFreezeTx:
				if !stxn.Txn.FreezeAccount.IsZero() {
					loadAccountsAddResourceTask(nil, basics.CreatableIndex(stxn.Txn.FreezeAsset), basics.AssetCreatable, task, resourceTasks, queue)
					loadAccountsAddResourceTask(&stxn.Txn.FreezeAccount, basics.CreatableIndex(stxn.Txn.FreezeAsset), basics.AssetCreatable, task, resourceTasks, queue)
					loadAccountsAddAccountTask(&stxn.Txn.FreezeAccount, task, accountTasks, queue)
				}
			case protocol.ApplicationCallTx:
				if stxn.Txn.ApplicationID != 0 {
					// load the global - so that we'll have the program
					loadAccountsAddResourceTask(nil, basics.CreatableIndex(stxn.Txn.ApplicationID), basics.AppCreatable, task, resourceTasks, queue)
					// load the local - so that we'll have the local state
					// TODO: this is something we need to decide if we want to enable, since not
					// every application call would use local storage.
					if (stxn.Txn.ApplicationCallTxnFields.OnCompletion == transactions.OptInOC) ||
						(stxn.Txn.ApplicationCallTxnFields.OnCompletion == transactions.CloseOutOC) ||
						(stxn.Txn.ApplicationCallTxnFields.OnCompletion == transactions.ClearStateOC) {
						loadAccountsAddResourceTask(&stxn.Txn.Sender, basics.CreatableIndex(stxn.Txn.ApplicationID), basics.AppCreatable, task, resourceTasks, queue)
					}
				}
				for _, fa := range stxn.Txn.ForeignApps {
					loadAccountsAddResourceTask(nil, basics.CreatableIndex(fa), basics.AppCreatable, task, resourceTasks, queue)
				}
				for _, fa := range stxn.Txn.ForeignAssets {
					loadAccountsAddResourceTask(nil, basics.CreatableIndex(fa), basics.AssetCreatable, task, resourceTasks, queue)
				}
				for ixa := range stxn.Txn.Accounts {
					loadAccountsAddAccountTask(&stxn.Txn.Accounts[ixa], task, accountTasks, queue)
				}
			case protocol.CompactCertTx:
			case protocol.KeyRegistrationTx:
			}
			// If you add new addresses here, also add them in getTxnAddresses().
			if !stxn.Txn.Sender.IsZero() {
				loadAccountsAddAccountTask(&stxn.Txn.Sender, task, accountTasks, queue)
			}
		}
		totalBalances += task.balancesCount
		totalResources += task.resourcesCount
		// expand the queue if needed.
		queue = queue.expand()
	}

	// find the number of tasks
	tasksCount := int64(0)
	for lastQueueEntry := &tasksQueue; ; lastQueueEntry = lastQueueEntry.next {
		if lastQueueEntry.next == nil {
			tasksCount = int64(lastQueueEntry.baseIdx + lastQueueEntry.used)
			break
		}
	}

	// update all the groups task :
	// allocate the correct number of balances, as well as
	// enough space on the "done" channel.
	allBalances := make([]LoadedAccountDataEntry, totalBalances)
	allResources := make([]LoadedResourcesEntry, totalResources)
	usedBalances := 0
	usedResources := 0

	// groupDoneCh is used to communicate the completion signal for a single
	// resource/address load between the go-routines and the main output channel
	// writer loop. The various go-routines would write to the channel the index
	// of the task that is complete and ready to be sent.
	groupDoneCh := make(chan groupTaskDone, len(groupsReady))
	const dependencyFreeGroup = -int64(^uint64(0)/2) - 1
	for grpIdx := range groupsReady {
		gr := &groupsReady[grpIdx]
		gr.groupTaskIndex = int64(grpIdx)
		gr.incompleteCount = int64(gr.balancesCount + gr.resourcesCount)
		gr.balances = allBalances[usedBalances : usedBalances+gr.balancesCount]
		if gr.resourcesCount > 0 {
			gr.resources = allResources[usedResources : usedResources+gr.resourcesCount]
			usedResources += gr.resourcesCount
		}
		usedBalances += gr.balancesCount
		if gr.incompleteCount == 0 {
			gr.incompleteCount = dependencyFreeGroup
		}
	}

	taskIdx := int64(-1)
	defer atomic.StoreInt64(&taskIdx, tasksCount)
	// create few go-routines to load asyncroniously the account data.
	for i := 0; i < asyncAccountLoadingThreadCount; i++ {
		go p.asyncPrefetchRoutine(&tasksQueue, &taskIdx, groupDoneCh)
	}

	// iterate on the transaction groups tasks. This array retains the original order.
	completed := make(map[int64]bool)
	for i := int64(0); i < int64(len(p.groups)); {
	wait:
		incompleteCount := atomic.LoadInt64(&groupsReady[i].incompleteCount)
		if incompleteCount > 0 || (incompleteCount != dependencyFreeGroup && !completed[i]) {
			select {
			case done := <-groupDoneCh:
				if done.err != nil {
					// if there is an error, report the error to the output channel.
					p.outChan <- LoadedTransactionGroup{
						Err: done.err,
					}
					return
				}
				if done.groupIdx > i {
					// mark future txn as ready.
					completed[done.groupIdx] = true
					goto wait
				} else if done.groupIdx < i {
					// it was already processed.
					goto wait
				}
			case <-ctx.Done():
				return
			}
		}
		next := i
		for ; next < int64(len(p.groups)); next++ {
			if !completed[next] {
				if next > i {
					i = next
					goto wait
				}
				// next == i
			}

			delete(completed, next)

			// if we had no error, write the result to the output channel.
			// this write will not block since we preallocated enough space on the channel.
			p.outChan <- LoadedTransactionGroup{
				TxnGroup:  p.groups[next],
				Accounts:  groupsReady[next].balances,
				Resources: groupsReady[next].resources,
			}
		}
		// if we get to this point, it means that we have no more transaction to process.
		break
	}
}

func (gt *groupTask) markCompletionAcct(idx int, br LoadedAccountDataEntry, groupDoneCh chan groupTaskDone) {
	gt.balances[idx] = br
	if atomic.AddInt64(&gt.incompleteCount, -1) == 0 {
		groupDoneCh <- groupTaskDone{groupIdx: gt.groupTaskIndex}
	}
}

func (gt *groupTask) markCompletionResource(idx int, res LoadedResourcesEntry, groupDoneCh chan groupTaskDone) {
	gt.resources[idx] = res
	if atomic.AddInt64(&gt.incompleteCount, -1) == 0 {
		groupDoneCh <- groupTaskDone{groupIdx: gt.groupTaskIndex}
	}
}

func (gt *groupTask) markCompletionAcctError(err error, groupDoneCh chan groupTaskDone) {
	for {
		curVal := atomic.LoadInt64(&gt.incompleteCount)
		if curVal <= 0 {
			return
		}
		if atomic.CompareAndSwapInt64(&gt.incompleteCount, curVal, 0) {
			groupDoneCh <- groupTaskDone{groupIdx: gt.groupTaskIndex, err: err}
			return
		}
	}
}

func (p *accountPrefetcher) asyncPrefetchRoutine(queue *preloaderTaskQueue, taskIdx *int64, groupDoneCh chan groupTaskDone) {
	var task *preloaderTask
	var err error
	for {
		nextTaskIdx := atomic.AddInt64(taskIdx, 1)
		queue, task = queue.getTaskAtIndex(int(nextTaskIdx))
		if task == nil {
			// no more tasks.
			return
		}
		if task.creatableIndex == 0 {
			// lookup the account data directly from the ledger.
			var acctData ledgercore.AccountData
			acctData, _, err = p.ledger.LookupWithoutRewards(p.rnd, *task.address)
			// if there was an error..
			if err != nil {
				// there was an error loading that entry.
				break
			}
			br := LoadedAccountDataEntry{
				Address: task.address,
				Data:    &acctData,
			}
			// update all the group tasks with the new acquired balance.
			for i, wt := range task.groups {
				wt.markCompletionAcct(task.groupIndices[i], br, groupDoneCh)
			}
			continue
		}
		if task.address == nil {
			// start off by figuring out the creator in case it's a global resource.
			var creator basics.Address
			var ok bool
			creator, ok, err = p.ledger.GetCreatorForRound(p.rnd, task.creatableIndex, task.creatableType)
			if err != nil {
				// there was an error loading that entry.
				break
			}
			if !ok {
				re := LoadedResourcesEntry{
					CreatableIndex: task.creatableIndex,
					CreatableType:  task.creatableType,
				}
				// update all the group tasks with the new acquired balance.
				for i, wt := range task.groups {
					wt.markCompletionResource(task.groupIndices[i], re, groupDoneCh)
				}
				continue
			}
			task.address = &creator
		}
		var resource ledgercore.AccountResource
		if task.creatableType == basics.AppCreatable {
			var appResource ledgercore.AppResource
			appResource, err = p.ledger.LookupApplication(p.rnd, *task.address, basics.AppIndex(task.creatableIndex))
			resource.AppParams = appResource.AppParams
			resource.AppLocalState = appResource.AppLocalState
		} else {
			var assetResource ledgercore.AssetResource
			assetResource, err = p.ledger.LookupAsset(p.rnd, *task.address, basics.AssetIndex(task.creatableIndex))
			resource.AssetParams = assetResource.AssetParams
			resource.AssetHolding = assetResource.AssetHolding
		}
		if err != nil {
			// there was an error loading that entry.
			break
		}
		re := LoadedResourcesEntry{
			Resource:       &resource,
			Address:        task.address,
			CreatableIndex: task.creatableIndex,
			CreatableType:  task.creatableType,
		}
		// update all the group tasks with the new acquired balance.
		for i, wt := range task.groups {
			wt.markCompletionResource(task.groupIndices[i], re, groupDoneCh)
		}
	}
	// if we got here, it means that there was an error.
	// in every case we get here, the task is gurenteed to be a non-nil.
	for _, wt := range task.groups {
		// notify the channel of the error.
		wt.markCompletionAcctError(err, groupDoneCh)
	}
}
