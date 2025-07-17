// Copyright (C) 2019-2025 Algorand, Inc.
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
	"fmt"
	"runtime"
	"sync/atomic"

	"github.com/algorand/avm-abi/apps"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// asyncAccountLoadingThreadCount controls how many go routines would be used
// to load the account data before the Eval() start processing individual
// transaction group.
var asyncAccountLoadingThreadCount = min(8, (runtime.NumCPU()+1)/2)

// Ledger is a ledger interfaces for prefetcher.
type Ledger interface {
	LookupWithoutRewards(basics.Round, basics.Address) (ledgercore.AccountData, basics.Round, error)
	LookupAsset(basics.Round, basics.Address, basics.AssetIndex) (ledgercore.AssetResource, error)
	LookupApplication(basics.Round, basics.Address, basics.AppIndex) (ledgercore.AppResource, error)
	GetCreatorForRound(basics.Round, basics.CreatableIndex, basics.CreatableType) (basics.Address, bool, error)
	LookupKv(basics.Round, string) ([]byte, error)
}

// LoadedAccountDataEntry describes a loaded account.
type LoadedAccountDataEntry struct {
	Address *basics.Address
	Data    *ledgercore.AccountData
}

// LoadedResourceEntry describes a loaded resource.
type LoadedResourceEntry struct {
	// Resource is the loaded Resource entry. unless address is nil, Resource would always contain a valid ledgercore.AccountResource pointer.
	Resource *ledgercore.AccountResource
	// Address might be empty if the resource does not exist. In that case creatableIndex and creatableType would still be valid while resource would be nil.
	Address        *basics.Address
	CreatableIndex basics.CreatableIndex
	CreatableType  basics.CreatableType
}

// LoadedKVEntry describes a loaded kv.
type LoadedKVEntry struct {
	// KV is the loaded kv entry.
	Key   string
	Value []byte
}

// LoadedTransactionGroup is a helper struct to allow asynchronous loading of the account data needed by the transaction groups
type LoadedTransactionGroup struct {
	// the transaction group
	TxnGroup []transactions.SignedTxnWithAD

	// Accounts is a list of all the Accounts balance records for the transaction group.
	Accounts []LoadedAccountDataEntry

	// Resources is the list of all Resources (apps/assets/hodling/locals) for the transaction group.
	Resources []LoadedResourceEntry

	// KVs is the list of all kvs for the transaction group
	KVs []LoadedKVEntry

	// Err indicates whether any of the balances in this structure have failed to load. In case of an error, at least
	// one of the entries in the balances would be uninitialized.
	Err error
}

// resourcePrefetcher used to prefetch accounts balances and resources before the evaluator is being called.
type resourcePrefetcher struct {
	ledger          Ledger
	rnd             basics.Round
	txnGroups       [][]transactions.SignedTxnWithAD
	feeSinkAddr     basics.Address
	consensusParams config.ConsensusParams
	outChan         chan LoadedTransactionGroup
}

// PrefetchResources loads the resources for the provided transaction group list. It also loads the feeSink account and add it to the first returned transaction group.
// The order of the transaction groups returned by the channel is identical to the one in the input array.
func PrefetchResources(ctx context.Context, l Ledger, rnd basics.Round, txnGroups [][]transactions.SignedTxnWithAD, feeSinkAddr basics.Address, consensusParams config.ConsensusParams) <-chan LoadedTransactionGroup {
	prefetcher := &resourcePrefetcher{
		ledger:          l,
		rnd:             rnd,
		txnGroups:       txnGroups,
		feeSinkAddr:     feeSinkAddr,
		consensusParams: consensusParams,
		outChan:         make(chan LoadedTransactionGroup, len(txnGroups)),
	}

	go prefetcher.prefetch(ctx)
	return prefetcher.outChan
}

// groupTask helps to organize the account loading for each transaction group.
type groupTask struct {
	// incompleteCount is the number of resources+balances still pending and need to be loaded
	// it is used to synchronize the readiness of the group task.
	incompleteCount atomic.Int64
	// the group task index - aligns with the index of the transaction group in the
	// provided groups slice.
	groupTaskIndex atomic.Int64

	// balances contains the loaded balances each transaction group have
	balances []LoadedAccountDataEntry
	// balancesCount is the number of balances that need to be loaded for this transaction group
	balancesCount int

	// resources contains the loaded resources each of the transaction groups have
	resources []LoadedResourceEntry
	// resourcesCount is the number of resources that need to be loaded for this transaction group
	resourcesCount int

	// kvs contains the loaded resources each of the transaction groups have
	kvs []LoadedKVEntry
	// kvCount is the number of kvs that need to be loaded for this transaction group
	kvCount int

	// error while processing this group task
	err error
}

// preloaderTask manage the loading of a single element, whether account, creatable, or kv
type preloaderTask struct {
	// account address to fetch
	address *basics.Address
	// resource id
	creatableIndex basics.CreatableIndex
	// resource type
	creatableType basics.CreatableType

	// key is the kv to fetch, if this is a kv task
	key string

	// the transaction group task to put the loaded data into
	groupTask *groupTask
	// the index at which to place the resource (int groupTask)
	groupTaskIndex int
}

// preloaderTaskQueue is a dynamic linked list of enqueued entries, optimized for non-synchronized insertion and
// synchronized extraction
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
	task     *preloaderTask
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

func (pq *preloaderTaskQueue) addAccountTask(addr *basics.Address, wt *groupTask, accountTasks map[basics.Address]*preloaderTask) {
	if addr.IsZero() {
		return
	}
	if _, have := accountTasks[*addr]; !have {
		newTask := &preloaderTask{
			address:        addr,
			groupTask:      wt,
			groupTaskIndex: wt.balancesCount,
		}
		wt.balancesCount++
		accountTasks[*addr] = newTask
		pq.enqueue(newTask)
	}
}

func (pq *preloaderTaskQueue) addResourceTask(addr *basics.Address, cidx basics.CreatableIndex, ctype basics.CreatableType, wt *groupTask, resourceTasks map[accountCreatableKey]*preloaderTask) {
	if cidx == 0 {
		return
	}
	key := accountCreatableKey{
		cidx: cidx,
	}
	if addr != nil {
		key.address = *addr
	}
	if _, have := resourceTasks[key]; !have {
		newTask := &preloaderTask{
			address:        addr,
			groupTask:      wt,
			groupTaskIndex: wt.resourcesCount,
			creatableIndex: cidx,
			creatableType:  ctype,
		}
		wt.resourcesCount++
		resourceTasks[key] = newTask
		pq.enqueue(newTask)
	}
}

func (pq *preloaderTaskQueue) addKvTask(app basics.AppIndex, name []byte, wt *groupTask, kvTasks map[string]*preloaderTask) {
	if app == 0 || len(name) == 0 {
		return
	}
	key := apps.MakeBoxKey(uint64(app), string(name))
	if _, have := kvTasks[key]; !have {
		newTask := &preloaderTask{
			key:            key,
			groupTask:      wt,
			groupTaskIndex: wt.kvCount,
		}
		wt.kvCount++
		kvTasks[key] = newTask
		pq.enqueue(newTask)
	}
}

// prefetch would process the input transaction groups by analyzing each of the transaction groups and building
// an execution queue that would allow us to fetch all the dependencies for the input transaction groups in order
// and output these onto a channel.
func (p *resourcePrefetcher) prefetch(ctx context.Context) {
	defer close(p.outChan)
	accountTasks := make(map[basics.Address]*preloaderTask)
	resourceTasks := make(map[accountCreatableKey]*preloaderTask)
	kvTasks := make(map[string]*preloaderTask)

	var maxTxnGroupEntries int
	if p.consensusParams.Application {
		// the extra two are for the sender account data, plus the application global state
		maxTxnGroupEntries = p.consensusParams.MaxTxGroupSize * (2 + p.consensusParams.MaxAppTotalTxnReferences)
	} else {
		// 8 is the number of resources+account used in the AssetTransferTx, which is the largest one.
		maxTxnGroupEntries = p.consensusParams.MaxTxGroupSize * 8
	}

	tasksQueue := allocPreloaderQueue(len(p.txnGroups), maxTxnGroupEntries)

	// totalBalances counts the total number of balances over all the transaction groups
	totalBalances := 0
	totalResources := 0
	totalKVs := 0

	// initialize empty groupTasks for groupsReady
	groupsReady := make([]*groupTask, len(p.txnGroups))
	for i := range groupsReady {
		groupsReady[i] = new(groupTask) // this ensures each allocated groupTask is 64-bit aligned
	}

	// Add fee sink to the first group
	if len(p.txnGroups) > 0 {
		// the feeSinkAddr is known to be non-empty
		feeSinkPreloader := &preloaderTask{
			address:        &p.feeSinkAddr,
			groupTask:      groupsReady[0],
			groupTaskIndex: 0,
		}
		groupsReady[0].balancesCount++
		accountTasks[p.feeSinkAddr] = feeSinkPreloader
		tasksQueue.enqueue(feeSinkPreloader)
	}

	// iterate over the transaction groups and add all their account addresses to the list
	queue := &tasksQueue
	for i := range p.txnGroups {
		task := groupsReady[i]
		for j := range p.txnGroups[i] {
			stxn := &p.txnGroups[i][j]
			switch stxn.Txn.Type {
			case protocol.PaymentTx:
				queue.addAccountTask(&stxn.Txn.Receiver, task, accountTasks)
				queue.addAccountTask(&stxn.Txn.CloseRemainderTo, task, accountTasks)
			case protocol.AssetConfigTx:
				queue.addResourceTask(nil, basics.CreatableIndex(stxn.Txn.ConfigAsset), basics.AssetCreatable, task, resourceTasks)
			case protocol.AssetTransferTx:
				if !stxn.Txn.AssetSender.IsZero() {
					queue.addResourceTask(nil, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks)
					queue.addResourceTask(&stxn.Txn.AssetSender, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks)
				} else {
					if stxn.Txn.AssetAmount == 0 && (stxn.Txn.AssetReceiver == stxn.Txn.Sender) { // opt in
						queue.addResourceTask(nil, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks)
					}
					if stxn.Txn.AssetAmount != 0 { // zero transfer is noop
						queue.addResourceTask(&stxn.Txn.Sender, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks)
					}
				}
				if !stxn.Txn.AssetReceiver.IsZero() {
					if stxn.Txn.AssetAmount != 0 || (stxn.Txn.AssetReceiver == stxn.Txn.Sender) {
						// if not zero transfer or opt in then prefetch
						queue.addResourceTask(&stxn.Txn.AssetReceiver, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks)
					}
				}
				if !stxn.Txn.AssetCloseTo.IsZero() {
					queue.addResourceTask(&stxn.Txn.AssetCloseTo, basics.CreatableIndex(stxn.Txn.XferAsset), basics.AssetCreatable, task, resourceTasks)
				}
			case protocol.AssetFreezeTx:
				if !stxn.Txn.FreezeAccount.IsZero() {
					queue.addResourceTask(nil, basics.CreatableIndex(stxn.Txn.FreezeAsset), basics.AssetCreatable, task, resourceTasks)
					queue.addResourceTask(&stxn.Txn.FreezeAccount, basics.CreatableIndex(stxn.Txn.FreezeAsset), basics.AssetCreatable, task, resourceTasks)
					queue.addAccountTask(&stxn.Txn.FreezeAccount, task, accountTasks)
				}
			case protocol.ApplicationCallTx:
				if stxn.Txn.ApplicationID != 0 {
					// load the global - so that we'll have the program
					queue.addResourceTask(nil, basics.CreatableIndex(stxn.Txn.ApplicationID), basics.AppCreatable, task, resourceTasks)
					// load the local - so that we'll have the local state
					// TODO: this is something we need to decide if we want to enable, since not
					// every application call would use local storage.
					if (stxn.Txn.ApplicationCallTxnFields.OnCompletion == transactions.OptInOC) ||
						(stxn.Txn.ApplicationCallTxnFields.OnCompletion == transactions.CloseOutOC) ||
						(stxn.Txn.ApplicationCallTxnFields.OnCompletion == transactions.ClearStateOC) {
						queue.addResourceTask(&stxn.Txn.Sender, basics.CreatableIndex(stxn.Txn.ApplicationID), basics.AppCreatable, task, resourceTasks)
					}
				}

				// do not preload Txn.ForeignApps, Txn.ForeignAssets, Txn.Accounts
				// since they might be non-used arbitrary values

				// prefetch boxes, they ought to be precise
				for _, br := range stxn.Txn.Boxes {
					if len(br.Name) == 0 {
						continue
					}
					app := stxn.Txn.ApplicationID
					if br.Index != 0 {
						app = stxn.Txn.ForeignApps[br.Index-1]
					}
					if app != 0 {
						queue.addKvTask(app, br.Name, task, kvTasks)
					}
				}

				// TODO: After tx.Access merge, prefetch everything from the list

			case protocol.StateProofTx:
			case protocol.KeyRegistrationTx: // No extra accounts besides the sender
			case protocol.HeartbeatTx:
				queue.addAccountTask(&stxn.Txn.HbAddress, task, accountTasks)
			}

			// If you add new addresses here, also add them in getTxnAddresses().
			if !stxn.Txn.Sender.IsZero() {
				queue.addAccountTask(&stxn.Txn.Sender, task, accountTasks)
			}
		}
		totalBalances += task.balancesCount
		totalResources += task.resourcesCount
		totalKVs += task.kvCount
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
	allResources := make([]LoadedResourceEntry, totalResources)
	allKVs := make([]LoadedKVEntry, totalKVs)
	usedBalances := 0
	usedResources := 0
	usedKVs := 0

	// groupDoneCh is used to communicate the completion signal for a single
	// resource/address load between the go-routines and the main output channel
	// writer loop. The various go-routines would write to the channel the index
	// of the task that is complete and ready to be sent.
	groupDoneCh := make(chan groupTaskDone, len(groupsReady))
	const dependencyFreeGroup = -int64(^uint64(0)/2) - 1
	for grpIdx := range groupsReady {
		gr := groupsReady[grpIdx]
		gr.groupTaskIndex.Store(int64(grpIdx))
		gr.incompleteCount.Store(int64(gr.balancesCount + gr.resourcesCount + gr.kvCount))
		gr.balances = allBalances[usedBalances : usedBalances+gr.balancesCount]
		usedBalances += gr.balancesCount
		gr.resources = allResources[usedResources : usedResources+gr.resourcesCount]
		usedResources += gr.resourcesCount
		gr.kvs = allKVs[usedKVs : usedKVs+gr.kvCount]
		usedKVs += gr.kvCount
		if gr.incompleteCount.Load() == 0 {
			gr.incompleteCount.Store(dependencyFreeGroup)
		}
	}

	var taskIdx atomic.Int64
	taskIdx.Store(-1)
	defer taskIdx.Store(tasksCount)
	// create few go-routines to load asyncroniously the account data.
	for range asyncAccountLoadingThreadCount {
		go p.asyncPrefetchRoutine(&tasksQueue, &taskIdx, groupDoneCh)
	}

	// iterate on the transaction groups tasks. This array retains the original order.
	completed := make(map[int64]bool)
	for i := int64(0); i < int64(len(p.txnGroups)); {
	wait:
		incompleteCount := groupsReady[i].incompleteCount.Load()
		if incompleteCount > 0 || (incompleteCount != dependencyFreeGroup && !completed[i]) {
			select {
			case done := <-groupDoneCh:
				if done.err != nil {
					groupsReady[done.groupIdx].err =
						fmt.Errorf("prefetch failed for groupIdx %d, address: %s, creatableIndex %d, creatableType %d, cause: %w",
							done.groupIdx, done.task.address, done.task.creatableIndex, done.task.creatableType, done.err)
				}
				if done.groupIdx > i {
					// mark future txngroup as ready.
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
		for ; next < int64(len(p.txnGroups)); next++ {
			if !completed[next] {
				if next > i {
					i = next
					goto wait
				}
				// next == i
			}

			delete(completed, next)

			// write the result to the output channel.
			// this write will not block since we preallocated enough space on the channel.
			p.outChan <- LoadedTransactionGroup{
				Err:       groupsReady[next].err,
				TxnGroup:  p.txnGroups[next],
				Accounts:  groupsReady[next].balances,
				Resources: groupsReady[next].resources,
				KVs:       groupsReady[next].kvs,
			}
		}
		// if we get to this point, it means that we have no more transaction to process.
		break
	}
}

func (gt *groupTask) markCompletionAcct(idx int, br LoadedAccountDataEntry, groupDoneCh chan groupTaskDone) {
	gt.balances[idx] = br
	if gt.incompleteCount.Add(-1) == 0 {
		groupDoneCh <- groupTaskDone{groupIdx: gt.groupTaskIndex.Load()}
	}
}

func (gt *groupTask) markCompletionResource(idx int, res LoadedResourceEntry, groupDoneCh chan groupTaskDone) {
	gt.resources[idx] = res
	if gt.incompleteCount.Add(-1) == 0 {
		groupDoneCh <- groupTaskDone{groupIdx: gt.groupTaskIndex.Load()}
	}
}

func (gt *groupTask) markCompletionKv(idx int, kv LoadedKVEntry, groupDoneCh chan groupTaskDone) {
	gt.kvs[idx] = kv
	if gt.incompleteCount.Add(-1) == 0 {
		groupDoneCh <- groupTaskDone{groupIdx: gt.groupTaskIndex.Load()}
	}
}

func (gt *groupTask) markCompletionError(err error, task *preloaderTask, groupDoneCh chan groupTaskDone) {
	for {
		curVal := gt.incompleteCount.Load()
		if curVal <= 0 {
			return
		}
		if gt.incompleteCount.CompareAndSwap(curVal, 0) {
			groupDoneCh <- groupTaskDone{
				groupIdx: gt.groupTaskIndex.Load(),
				err:      err,
				task:     task,
			}
			return
		}
	}
}

func (p *resourcePrefetcher) asyncPrefetchRoutine(queue *preloaderTaskQueue, taskIdx *atomic.Int64, groupDoneCh chan groupTaskDone) {
	var task *preloaderTask
	var err error
	for {
		nextTaskIdx := taskIdx.Add(1)
		queue, task = queue.getTaskAtIndex(int(nextTaskIdx))
		if task == nil {
			// no more tasks.
			return
		}
		if task.key != "" {
			var value []byte
			value, err = p.ledger.LookupKv(p.rnd, task.key)
			if err != nil {
				// notify the channel of the error.
				task.groupTask.markCompletionError(err, task, groupDoneCh)
				continue
			}
			br := LoadedKVEntry{
				Key:   task.key,
				Value: value,
			}
			task.groupTask.markCompletionKv(task.groupTaskIndex, br, groupDoneCh)
			continue
		}
		if task.creatableIndex == 0 {
			// lookup the account data directly from the ledger.
			var acctData ledgercore.AccountData
			acctData, _, err = p.ledger.LookupWithoutRewards(p.rnd, *task.address)
			if err != nil {
				// notify the channel of the error.
				task.groupTask.markCompletionError(err, task, groupDoneCh)
				continue
			}
			br := LoadedAccountDataEntry{
				Address: task.address,
				Data:    &acctData,
			}
			task.groupTask.markCompletionAcct(task.groupTaskIndex, br, groupDoneCh)
			continue
		}
		if task.address == nil {
			// start off by figuring out the creator in case it's a global resource.
			var creator basics.Address
			var ok bool
			creator, ok, err = p.ledger.GetCreatorForRound(p.rnd, task.creatableIndex, task.creatableType)
			if err != nil {
				// there was an error loading that entry.
				task.groupTask.markCompletionError(err, task, groupDoneCh)
				continue
			}
			if !ok {
				re := LoadedResourceEntry{
					CreatableIndex: task.creatableIndex,
					CreatableType:  task.creatableType,
				}
				// update all the group tasks with the new acquired balance.
				task.groupTask.markCompletionResource(task.groupTaskIndex, re, groupDoneCh)
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
			// notify the channel of the error.
			task.groupTask.markCompletionError(err, task, groupDoneCh)
			continue
		}
		re := LoadedResourceEntry{
			Resource:       &resource,
			Address:        task.address,
			CreatableIndex: task.creatableIndex,
			CreatableType:  task.creatableType,
		}
		// update the group task with the new acquired balance.
		task.groupTask.markCompletionResource(task.groupTaskIndex, re, groupDoneCh)
	}
}
