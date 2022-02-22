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

type loadedAccountDataEntry struct {
	address *basics.Address
	data    *ledgercore.AccountData
}

type loadedResourcesEntry struct {
	// resource is the loaded resource entry. unless address is nil, resource would always contain a valid ledgercore.AccountResource pointer.
	resource *ledgercore.AccountResource
	// address might be empty if the resource does not exist. In that case creatableIndex and creatableType would still be valid while resource would be nil.
	address        *basics.Address
	creatableIndex basics.CreatableIndex
	creatableType  basics.CreatableType
}

// loadedTransactionGroup is a helper struct to allow asynchronous loading of the account data needed by the transaction groups
type loadedTransactionGroup struct {
	// accounts is a list of all the accounts balance records that the transaction group refer to and are needed.
	accounts []loadedAccountDataEntry

	// the following four are the resources used by the account
	resources []loadedResourcesEntry

	// err indicates whether any of the balances in this structure have failed to load. In case of an error, at least
	// one of the entries in the balances would be uninitialized.
	err error
}

// accountPrefetcher used to prefetch accounts balances and resources before the evaluator is being called.
type accountPrefetcher struct {
	ledger          LedgerForEvaluator
	rnd             basics.Round
	groups          [][]transactions.SignedTxnWithAD
	feeSinkAddr     basics.Address
	consensusParams config.ConsensusParams
	outChan         chan loadedTransactionGroup
}

// loadAccounts loads the account data for the provided transaction group list. It also loads the feeSink account and add it to the first returned transaction group.
// The order of the transaction groups returned by the channel is identical to the one in the input array.
func prefetchAccounts(ctx context.Context, l LedgerForEvaluator, rnd basics.Round, groups [][]transactions.SignedTxnWithAD, feeSinkAddr basics.Address, consensusParams config.ConsensusParams) <-chan loadedTransactionGroup {
	prefetcher := &accountPrefetcher{
		ledger:          l,
		rnd:             rnd,
		groups:          groups,
		feeSinkAddr:     feeSinkAddr,
		consensusParams: consensusParams,
		outChan:         make(chan loadedTransactionGroup, len(groups)),
	}

	go prefetcher.prefetch(ctx)
	return prefetcher.outChan
}

// groupTask helps to organize the account loading for each transaction group.
type groupTask struct {
	groupTaskIndex int
	// balances contains the loaded balances each transaction group have
	balances []loadedAccountDataEntry
	// balancesCount is the number of balances that nees to be loaded per transaction group
	balancesCount int
	// resources contains the loaded resources each of the transaction groups have
	resources []loadedResourcesEntry
	// resourcesCount is the number of resources that nees to be loaded per transaction group
	resourcesCount int
	// incompleteCount is the number of resources+balances still pending and need to be loaded
	incompleteCount int64
	// err indicates the error code ( if any ) that was received from the ledger during execution
	err error
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

// preloaderTaskQueue is a dynamic linked list of enqueued entries, optimized for non-syncronized insertion and
// syncronized extraction
type preloaderTaskQueue struct {
	next               *preloaderTaskQueue
	used               int
	entries            []*preloaderTask
	baseIdx            int
	maxTxnGroupEntries int
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
	return
}

func (pq *preloaderTaskQueue) expand() *preloaderTaskQueue {
	if cap(pq.entries)-pq.used < pq.maxTxnGroupEntries {
		pq.next = &preloaderTaskQueue{
			entries: make([]*preloaderTask, cap(pq.entries)*2),
			used:    0,
			baseIdx: pq.baseIdx + pq.used,
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

func loadAccountsAddAccountTask(addr *basics.Address, wg *groupTask, accountTasks map[basics.Address]*preloaderTask, queue *preloaderTaskQueue) {
	if addr.IsZero() {
		return
	}
	if task, have := accountTasks[*addr]; !have {
		task := &preloaderTask{
			address:      addr,
			groups:       make([]*groupTask, 1, 4),
			groupIndices: make([]int, 1, 4),
		}
		task.groups[0] = wg
		task.groupIndices[0] = wg.balancesCount

		accountTasks[*addr] = task
		queue.enqueue(task)
	} else {
		task.groups = append(task.groups, wg)
		task.groupIndices = append(task.groupIndices, wg.balancesCount)
	}
	wg.balancesCount++
}

func loadAccountsAddResourceTask(addr *basics.Address, cidx basics.CreatableIndex, ctype basics.CreatableType, wg *groupTask, resourceTasks map[accountCreatableKey]*preloaderTask, queue *preloaderTaskQueue) {
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
		task.groups[0] = wg
		task.groupIndices[0] = wg.resourcesCount

		resourceTasks[key] = task
		queue.enqueue(task)
	} else {
		task.groups = append(task.groups, wg)
		task.groupIndices = append(task.groupIndices, wg.resourcesCount)
	}
	wg.resourcesCount++
}

func (p *accountPrefetcher) prefetch(ctx context.Context) {
	defer close(p.outChan)
	accountTasks := make(map[basics.Address]*preloaderTask)
	resourceTasks := make(map[accountCreatableKey]*preloaderTask)

	var maxTxnGroupEntries = config.MaxTxGroupSize * (config.MaxAppTxnAccounts + config.MaxAppTxnForeignApps + config.MaxAppTxnForeignAssets)

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
				loadAccountsAddResourceTask(&stxn.Txn.Sender, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, queue)
				if !stxn.Txn.AssetSender.IsZero() {
					loadAccountsAddResourceTask(&stxn.Txn.AssetSender, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, queue)
					loadAccountsAddAccountTask(&stxn.Txn.AssetSender, task, accountTasks, queue)
				}
				if !stxn.Txn.AssetReceiver.IsZero() {
					loadAccountsAddResourceTask(&stxn.Txn.AssetReceiver, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, queue)
					loadAccountsAddAccountTask(&stxn.Txn.AssetReceiver, task, accountTasks, queue)
				}
				if !stxn.Txn.AssetCloseTo.IsZero() {
					loadAccountsAddResourceTask(&stxn.Txn.AssetCloseTo, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks, queue)
					loadAccountsAddAccountTask(&stxn.Txn.AssetCloseTo, task, accountTasks, queue)
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
					// this is something we need to decide if we want to enable, since not every application call would use local storage.
					//loadAccountsAddResourceTask(&stxn.Txn.Sender, basics.CreatableIndex(stxn.Txn.ApplicationID), basics.AppCreatable, task, resourceTasks, queue)
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
				fallthrough
			case protocol.KeyRegistrationTx:
				fallthrough
			default:
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
	allBalances := make([]loadedAccountDataEntry, totalBalances)
	allResources := make([]loadedResourcesEntry, totalResources)
	usedBalances := 0
	usedResources := 0

	groupDoneCh := make(chan int, len(groupsReady))
	const dependencyFreeGroup = -int64(^uint64(0)/2) - 1
	for grpIdx := range groupsReady {
		gr := &groupsReady[grpIdx]
		gr.groupTaskIndex = grpIdx
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
	completed := make(map[int]bool)
	for i := 0; i < len(p.groups); {
	wait:
		if incompleteCount := atomic.LoadInt64(&groupsReady[i].incompleteCount); incompleteCount > 0 || (incompleteCount != dependencyFreeGroup && !completed[i]) {
			select {
			case doneIdx := <-groupDoneCh:
				if doneIdx < 0 {
					doneIdx = -doneIdx
					// if there is an error, report the error to the output channel.
					p.outChan <- loadedTransactionGroup{
						err: groupsReady[doneIdx].err,
					}
					return
				}
				if doneIdx > i {
					// mark future txn as ready.
					completed[doneIdx] = true
					goto wait
				} else if doneIdx < i {
					// it was already processed.
					goto wait
				}
			case <-ctx.Done():
				return
			}
		}
		next := i
		for ; next < len(p.groups); next++ {
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
			p.outChan <- loadedTransactionGroup{
				accounts:  groupsReady[next].balances,
				resources: groupsReady[next].resources,
			}
		}
		// if we get to this point, it means that we have no more transaction to process.
		break
	}
}

func (wg *groupTask) markCompletionAcct(idx int, br loadedAccountDataEntry, groupDoneCh chan int) {
	wg.balances[idx] = br
	if 0 == atomic.AddInt64(&wg.incompleteCount, -1) {
		groupDoneCh <- wg.groupTaskIndex
	}
}

func (wg *groupTask) markCompletionResource(idx int, res loadedResourcesEntry, groupDoneCh chan int) {
	wg.resources[idx] = res
	if 0 == atomic.AddInt64(&wg.incompleteCount, -1) {
		groupDoneCh <- wg.groupTaskIndex
	}
}

func (wg *groupTask) markCompletionAcctError(err error, groupDoneCh chan int) {
	for {
		curVal := atomic.LoadInt64(&wg.incompleteCount)
		if curVal <= 0 {
			return
		}
		if atomic.CompareAndSwapInt64(&wg.incompleteCount, curVal, 0) {
			wg.err = err
			groupDoneCh <- -wg.groupTaskIndex
			return
		}
	}
}

func (p *accountPrefetcher) asyncPrefetchRoutine(queue *preloaderTaskQueue, taskIdx *int64, groupDoneCh chan int) {
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
			br := loadedAccountDataEntry{
				address: task.address,
				data:    &acctData,
			}
			// update all the group tasks with the new acquired balance.
			for i, wg := range task.groups {
				wg.markCompletionAcct(task.groupIndices[i], br, groupDoneCh)
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
				re := loadedResourcesEntry{
					creatableIndex: task.creatableIndex,
					creatableType:  task.creatableType,
				}
				// update all the group tasks with the new acquired balance.
				for i, wg := range task.groups {
					wg.markCompletionResource(task.groupIndices[i], re, groupDoneCh)
				}
				continue
			}
			task.address = &creator
		}
		var resource ledgercore.AccountResource
		resource, err = p.ledger.LookupResource(p.rnd, *task.address, task.creatableIndex, task.creatableType)
		if err != nil {
			// there was an error loading that entry.
			break
		}
		re := loadedResourcesEntry{
			resource:       &resource,
			address:        task.address,
			creatableIndex: task.creatableIndex,
			creatableType:  task.creatableType,
		}
		// update all the group tasks with the new acquired balance.
		for i, wg := range task.groups {
			wg.markCompletionResource(task.groupIndices[i], re, groupDoneCh)
		}
	}
	// if we got here, it means that there was an error.
	if task != nil {
		for _, wg := range task.groups {
			// notify the channel of the error.
			wg.markCompletionAcctError(err, groupDoneCh)
		}
	}
}
