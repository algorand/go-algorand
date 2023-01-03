// Copyright (C) 2019-2023 Algorand, Inc.
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

package data

import (
	"bytes"
	"container/heap"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/pools"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/metrics"
)

var transactionMessagesHandled = metrics.MakeCounter(metrics.TransactionMessagesHandled)
var transactionMessagesDroppedFromBacklog = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromBacklog)
var transactionMessagesDroppedFromPool = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromPool)
var txAdvertiseDrops = metrics.NewCounter("algod_tx_advertise_drops", "Number of Ta messages dropped")
var txAdvertiseErr = metrics.NewCounter("algod_tx_advertise_err", "Number of Ta messages errored")
var txAdvertiseProg = metrics.NewCounter("algod_tx_advertise_prog", "Number of Ta messages in progress")
var txAdvertisePCache = metrics.NewCounter("algod_tx_advertise_pcache", "Number of Ta messages found in pcache")
var txAdvertisePool = metrics.NewCounter("algod_tx_advertise_pool", "Number of Ta messages found in pool")
var txRequest = metrics.NewCounter("algod_tx_request_out", "Number of Tr messages sent first pass")
var txRequestRetry = metrics.NewCounter("algod_tx_request_out_retry", "Number of Tr messages sent to a second peer")
var txRequestIn = metrics.NewCounter("algod_tx_request_in", "Number of Tr messages in at handler")
var txRequestInErr = metrics.NewCounter("algod_tx_request_in_err", "Number of Tr err in handler")
var txRequestInOk = metrics.NewCounter("algod_tx_request_in_ok", "Number of Tr messages replied at handler")
var txRequestInMiss = metrics.NewCounter("algod_tx_request_in_miss", "Number of Tr messages missing at handler")
var transactionMessagesAlreadyCommitted = metrics.MakeCounter(metrics.TransactionMessagesAlreadyCommitted)
var transactionMessagesTxGroupInvalidFee = metrics.MakeCounter(metrics.TransactionMessagesTxGroupInvalidFee)
var transactionMessagesTxnNotWellFormed = metrics.MakeCounter(metrics.TransactionMessagesTxnNotWellFormed)
var transactionMessagesTxnSigNotWellFormed = metrics.MakeCounter(metrics.TransactionMessagesTxnSigNotWellFormed)
var transactionMessagesTxnMsigNotWellFormed = metrics.MakeCounter(metrics.TransactionMessagesTxnMsigNotWellFormed)
var transactionMessagesTxnLogicSig = metrics.MakeCounter(metrics.TransactionMessagesTxnLogicSig)
var transactionMessagesTxnSigVerificationFailed = metrics.MakeCounter(metrics.TransactionMessagesTxnSigVerificationFailed)
var transactionMessagesBacklogErr = metrics.MakeCounter(metrics.TransactionMessagesBacklogErr)
var transactionMessagesRemember = metrics.MakeCounter(metrics.TransactionMessagesRemember)
var transactionMessageTxGroupExcessive = metrics.MakeCounter(metrics.TransactionMessageTxGroupExcessive)
var transactionMessageTxGroupFull = metrics.MakeCounter(metrics.TransactionMessageTxGroupFull)
var transactionMessagesDupRawMsg = metrics.MakeCounter(metrics.TransactionMessagesDupRawMsg)
var transactionMessagesDupCanonical = metrics.MakeCounter(metrics.TransactionMessagesDupCanonical)
var transactionMessagesBacklogSizeGauge = metrics.MakeGauge(metrics.TransactionMessagesBacklogSize)

var transactionGroupTxSyncHandled = metrics.MakeCounter(metrics.TransactionGroupTxSyncHandled)
var transactionGroupTxSyncRemember = metrics.MakeCounter(metrics.TransactionGroupTxSyncRemember)
var transactionGroupTxSyncAlreadyCommitted = metrics.MakeCounter(metrics.TransactionGroupTxSyncAlreadyCommitted)
var txBacklogDroppedCongestionManagement = metrics.MakeCounter(metrics.TransactionMessagesTxnDroppedCongestionManagement)

// ErrInvalidTxPool is reported when nil is passed for the tx pool
var ErrInvalidTxPool = errors.New("MakeTxHandler: txPool is nil on initialization")

// ErrInvalidLedger is reported when nil is passed for the ledger
var ErrInvalidLedger = errors.New("MakeTxHandler: ledger is nil on initialization")

var transactionMessageTxPoolRememberCounter = metrics.NewTagCounter(
	"algod_transaction_messages_txpool_remember_err_{TAG}", "Number of transaction messages not remembered by txpool b/c of {TAG}",
	txPoolRememberTagCap, txPoolRememberPendingEval, txPoolRememberTagNoSpace, txPoolRememberTagFee, txPoolRememberTagTxnDead, txPoolRememberTagTxnEarly, txPoolRememberTagTooLarge, txPoolRememberTagGroupID,
	txPoolRememberTagTxID, txPoolRememberTagLease, txPoolRememberTagTxIDEval, txPoolRememberTagLeaseEval, txPoolRememberTagEvalGeneric,
)

var transactionMessageTxPoolCheckCounter = metrics.NewTagCounter(
	"algod_transaction_messages_txpool_check_err_{TAG}", "Number of transaction messages that didn't pass check by txpool b/c of {TAG}",
	txPoolRememberTagTxnNotWellFormed, txPoolRememberTagTxnDead, txPoolRememberTagTxnEarly, txPoolRememberTagTooLarge, txPoolRememberTagGroupID,
	txPoolRememberTagTxID, txPoolRememberTagLease, txPoolRememberTagTxIDEval, txPoolRememberTagLeaseEval, txPoolRememberTagEvalGeneric,
)

const (
	txPoolRememberTagCap         = "cap"
	txPoolRememberPendingEval    = "pending_eval"
	txPoolRememberTagNoSpace     = "no_space"
	txPoolRememberTagFee         = "fee"
	txPoolRememberTagTxnDead     = "txn_dead"
	txPoolRememberTagTxnEarly    = "txn_early"
	txPoolRememberTagTooLarge    = "too_large"
	txPoolRememberTagGroupID     = "groupid"
	txPoolRememberTagTxID        = "txid"
	txPoolRememberTagLease       = "lease"
	txPoolRememberTagTxIDEval    = "txid_eval"
	txPoolRememberTagLeaseEval   = "lease_eval"
	txPoolRememberTagEvalGeneric = "eval"

	txPoolRememberTagTxnNotWellFormed = "not_well"
)

// The txBacklogMsg structure used to track a single incoming transaction from the gossip network,
type txBacklogMsg struct {
	rawmsg                *network.IncomingMessage // the raw message from the network
	unverifiedTxGroup     []transactions.SignedTxn // the unverified ( and signed ) transaction group
	rawmsgDataHash        *crypto.Digest           // hash (if any) of raw message data from the network
	unverifiedTxGroupHash *crypto.Digest           // hash (if any) of the unverifiedTxGroup
	verificationErr       error                    // The verification error generated by the verification function, if any.
	capguard              *util.ErlCapacityGuard   // the structure returned from the elastic rate limiter, to be released when dequeued
}

// TxHandler handles transaction messages
type TxHandler struct {
	txPool                *pools.TransactionPool
	ledger                *Ledger
	log                   logging.Logger
	genesisID             string
	genesisHash           crypto.Digest
	txVerificationPool    execpool.BacklogPool
	backlogQueue          chan *txBacklogMsg
	postVerificationQueue chan *verify.VerificationResult
	txAdvertiseQueue      chan network.IncomingMessage
	txidRequestDone       chan []transactions.Txid
	backlogWg             sync.WaitGroup
	net                   network.GossipNode
	msgCache              *txSaltedCache
	txCanonicalCache      *digestCache
	cacheConfig           txHandlerConfig
	ctx                   context.Context
	ctxCancel             context.CancelFunc

	relayMessages bool

	// prevRound atomic set by OnNewBlock
	prevRound uint64

	txRequests requestedTxnSet

	// prevTxns contains the stxns from the previous block.
	// The value is map[transactions.Txid]SignedTxn
	prevTxns atomic.Value

	streamVerifier        *verify.StreamVerifier
	streamVerifierChan    chan *verify.UnverifiedElement
	streamVerifierDropped chan *verify.UnverifiedElement
	erl                   *util.ElasticRateLimiter
}

// We need to store txns we have seen:
// * Until one round after they have committed, other nodes could still be fetching them to validate what we see as the 'previous' round.
// * Until they expire by LastValid. (txPool does this)
// * Fetch them by txid when requested by a peer
//
// We store advertisements of txid:
// * Until we have the stxn, then it's in the tx pool.
// * Until the request times out and no other advertising peer is available to query
//
// data.Ledger.LookupTxid() is horribly expensive, inflating the entire block's Txns, calculating Txid one by one, and then throwing away the set when done.

type requestedTxn struct {
	txid          transactions.Txid
	requestedFrom []network.Peer
	advertisedBy  []network.Peer
	requestedAt   time.Time
	heapPos       int
}

type requestedTxnSet struct {
	// ar contains a heap ordered by .requestedAt
	ar     []*requestedTxn
	byTxid map[transactions.Txid]*requestedTxn
}

// Len is part of sort.Interface and container/heap.Interface
func (rts *requestedTxnSet) Len() int {
	return len(rts.ar)
}

// Less is part of sort.Interface and container/heap.Interface
func (rts *requestedTxnSet) Less(i, j int) bool {
	return rts.ar[i].requestedAt.Before(rts.ar[j].requestedAt)
}

// Swap is part of sort.Interface and container/heap.Interface
func (rts *requestedTxnSet) Swap(i, j int) {
	t := rts.ar[i]
	rts.ar[i] = rts.ar[j]
	rts.ar[j] = t
	rts.ar[i].heapPos = i
	rts.ar[j].heapPos = j
}

// Push is part of container/heap.Interface
func (rts *requestedTxnSet) Push(x interface{}) {
	req := x.(*requestedTxn)
	last := len(rts.ar)
	req.heapPos = last
	rts.ar = append(rts.ar, req)
}

// Pop is part of container/heap.Interface
func (rts *requestedTxnSet) Pop() interface{} {
	last := len(rts.ar) - 1
	out := rts.ar[last]
	rts.ar[last] = nil
	out.heapPos = -1
	rts.ar = rts.ar[:last]
	return out
}

func (rts *requestedTxnSet) add(x *requestedTxn) {
	if rts.byTxid == nil {
		rts.byTxid = make(map[transactions.Txid]*requestedTxn)
	}
	rts.byTxid[x.txid] = x
	heap.Push(rts, x)
}

func (rts *requestedTxnSet) getByTxid(txid transactions.Txid) (x *requestedTxn, ok bool) {
	x, ok = rts.byTxid[txid]
	return x, ok
}

func (rts *requestedTxnSet) popByTxid(txid transactions.Txid) (x *requestedTxn, ok bool) {
	x, ok = rts.byTxid[txid]
	if ok {
		delete(rts.byTxid, txid)
		if x.heapPos < 0 {
			panic(fmt.Sprintf("txid %s heapPos %d", txid.String(), x.heapPos))
		}
		if x.heapPos >= len(rts.ar) {
			panic(fmt.Sprintf("txid %s heapPos %d of %d", txid.String(), x.heapPos, len(rts.ar)))
		}
		heap.Remove(rts, x.heapPos)
	}
	return x, ok
}

// TxHandlerOpts is TxHandler configuration options
type TxHandlerOpts struct {
	TxPool        *pools.TransactionPool
	ExecutionPool execpool.BacklogPool
	Ledger        *Ledger
	Net           network.GossipNode
	GenesisID     string
	GenesisHash   crypto.Digest
	Config        config.Local
}

// txHandlerConfig is a subset of tx handler related options from config.Local
type txHandlerConfig struct {
	enableFilteringRawMsg    bool
	enableFilteringCanonical bool
}

// MakeTxHandler makes a new handler for transaction messages
func MakeTxHandler(opts TxHandlerOpts) (*TxHandler, error) {

	if opts.TxPool == nil {
		return nil, ErrInvalidTxPool
	}

	if opts.Ledger == nil {
		return nil, ErrInvalidLedger
	}

	// backlog size is big enough for each peer to have its reserved capacity in the backlog, plus the config's backlogSize as a shared capacity
	txBacklogSize := opts.Config.TxBacklogSize
	if opts.Config.EnableTxBacklogRateLimiting {
		txBacklogSize += (opts.Config.IncomingConnectionsLimit * opts.Config.TxBacklogReservedCapacityPerPeer)
	}

	handler := &TxHandler{
		txPool:                opts.TxPool,
		genesisID:             opts.GenesisID,
		genesisHash:           opts.GenesisHash,
		ledger:                opts.Ledger,
		log:                   opts.Ledger.log,
		txVerificationPool:    opts.ExecutionPool,
		backlogQueue:          make(chan *txBacklogMsg, txBacklogSize),
		postVerificationQueue: make(chan *verify.VerificationResult, txBacklogSize),
		txAdvertiseQueue:      make(chan network.IncomingMessage, txBacklogSize),
		txidRequestDone:       make(chan []transactions.Txid, txBacklogSize),
		net:                   opts.Net,
		relayMessages:         opts.Config.NetAddress != "" || opts.Config.ForceRelayMessages,
		msgCache:              makeSaltedCache(2 * txBacklogSize),
		txCanonicalCache:      makeDigestCache(2 * txBacklogSize),
		cacheConfig:           txHandlerConfig{opts.Config.TxFilterRawMsgEnabled(), opts.Config.TxFilterCanonicalEnabled()},
		streamVerifierChan:    make(chan *verify.UnverifiedElement),
		streamVerifierDropped: make(chan *verify.UnverifiedElement),
	}

	if opts.Config.EnableTxBacklogRateLimiting {
		rateLimiter := util.NewElasticRateLimiter(
			txBacklogSize,
			opts.Config.TxBacklogReservedCapacityPerPeer,
			time.Duration(opts.Config.TxBacklogServiceRateWindowSeconds)*time.Second,
			txBacklogDroppedCongestionManagement,
		)
		handler.erl = rateLimiter
	}

	// prepare the transaction stream verifer
	var err error
	handler.streamVerifier, err = verify.MakeStreamVerifier(handler.streamVerifierChan,
		handler.postVerificationQueue, handler.streamVerifierDropped, handler.ledger,
		handler.txVerificationPool, handler.ledger.VerifiedTransactionCache())
	if err != nil {
		return nil, err
	}
	handler.ledger.Ledger.RegisterBlockListeners([]ledgercore.BlockListener{handler})
	go handler.droppedTxnWatcher()
	return handler, nil
}

func (handler *TxHandler) droppedTxnWatcher() {
	for unverified := range handler.streamVerifierDropped {
		// we failed to write to the output queue, since the queue was full.
		// adding the metric here allows us to monitor how frequently it happens.
		transactionMessagesDroppedFromPool.Inc(nil)

		tx := unverified.BacklogMessage.(*txBacklogMsg)

		// delete from duplicate caches to give it a chance to be re-submitted
		handler.deleteFromCaches(tx.rawmsgDataHash, tx.unverifiedTxGroupHash)
	}
}

// OnNewBlock is part of ledger.BlockListener interface
func (handler *TxHandler) OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta) {
	stxns, err := block.DecodePaysetFlat()
	if err != nil {
		handler.log.Errorf("txHandler OnNewBlock DecodePaysetFlat: %v", err)
		return
	}
	txidList := make([]transactions.Txid, len(stxns))
	prevTxns := make(map[transactions.Txid]transactions.SignedTxn, len(stxns))
	for i, stxn := range stxns {
		txid := stxn.ID()
		prevTxns[txid] = stxn.SignedTxn
		txidList[i] = txid
	}
	handler.txidRequestDone <- txidList
	handler.prevTxns.Store(prevTxns)
	atomic.StoreUint64(&handler.prevRound, uint64(block.BlockHeader.Round))
}

// Start enables the processing of incoming messages at the transaction handler
func (handler *TxHandler) Start() {
	handler.ctx, handler.ctxCancel = context.WithCancel(context.Background())
	handler.msgCache.Start(handler.ctx, 60*time.Second)
	handler.net.RegisterHandlers([]network.TaggedMessageHandler{
		{
			Tag:            protocol.TxnTag,
			MessageHandler: network.HandlerFunc(handler.processIncomingTxn),
		},
		{
			Tag:            protocol.TxnAdvertiseTag,
			MessageHandler: network.HandlerFunc(handler.processIncomingTxnAdvertise),
		},
		{
			Tag:            protocol.TxnRequestTag,
			MessageHandler: network.HandlerFunc(handler.processIncomingTxnRequest),
		},
	})
	handler.backlogWg.Add(3)
	go handler.backlogWorker()
	go handler.backlogGaugeThread()
	go handler.retryHandler()
	handler.streamVerifier.Start(handler.ctx)
	if handler.erl != nil {
		handler.erl.Start()
	}
}

// Stop suspends the processing of incoming messages at the transaction handler
func (handler *TxHandler) Stop() {
	handler.ctxCancel()
	if handler.erl != nil {
		handler.erl.Stop()
	}
	handler.backlogWg.Wait()
	handler.streamVerifier.WaitForStop()
	handler.msgCache.WaitForStop()
}

func reencode(stxns []transactions.SignedTxn) []byte {
	var result [][]byte
	for i := range stxns {
		result = append(result, protocol.Encode(&stxns[i]))
	}
	return bytes.Join(result, nil)
}

func (handler *TxHandler) backlogGaugeThread() {
	defer handler.backlogWg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			transactionMessagesBacklogSizeGauge.Set(float64(len(handler.backlogQueue)))
		case <-handler.ctx.Done():
			return
		}
	}
}

// backlogWorker is the worker go routine that process the incoming messages from the postVerificationQueue and backlogQueue channels
// and dispatches them further.
func (handler *TxHandler) backlogWorker() {
	// Note: TestIncomingTxHandle and TestIncomingTxGroupHandle emulate this function.
	// Changes to the behavior in this function should be reflected in the test.
	defer handler.backlogWg.Done()
	for {
		// prioritize the postVerificationQueue
		select {
		case wi, ok := <-handler.postVerificationQueue:
			if !ok {
				return
			}
			m := wi.BacklogMessage.(*txBacklogMsg)
			m.verificationErr = wi.Err
			handler.postProcessCheckedTxn(m)

			// restart the loop so that we could empty out the post verification queue.
			continue
		default:
		}

		// we have no more post verification items. wait for either backlog queue item or post verification item.
		select {
		case wi, ok := <-handler.backlogQueue:
			if !ok {
				// this is never happening since handler.backlogQueue is never closed
				return
			}
			if wi.capguard != nil {
				if err := wi.capguard.Release(); err != nil {
					logging.Base().Warnf("Failed to release capacity to ElasticRateLimiter: %v", err)
				}
			}
			if handler.checkAlreadyCommitted(wi) {
				transactionMessagesAlreadyCommitted.Inc(nil)
				if wi.capguard != nil {
					wi.capguard.Served()
				}
				continue
			}
			// handler.streamVerifierChan does not receive if ctx is cancled
			select {
			case handler.streamVerifierChan <- &verify.UnverifiedElement{TxnGroup: wi.unverifiedTxGroup, BacklogMessage: wi}:
			case <-handler.ctx.Done():
				transactionMessagesDroppedFromBacklog.Inc(nil)
				return
			}
			if wi.capguard != nil {
				wi.capguard.Served()
			}
		case wi, ok := <-handler.postVerificationQueue:
			if !ok {
				// this is never happening since handler.postVerificationQueue is never closed
				return
			}
			m := wi.BacklogMessage.(*txBacklogMsg)
			m.verificationErr = wi.Err
			handler.postProcessCheckedTxn(m)

		case <-handler.ctx.Done():
			return
		}
	}
}

func (handler *TxHandler) postProcessReportErrors(err error) {
	if errors.Is(err, crypto.ErrBatchHasFailedSigs) {
		transactionMessagesTxnSigVerificationFailed.Inc(nil)
		return
	}

	var txGroupErr *verify.TxGroupError
	if errors.As(err, &txGroupErr) {
		switch txGroupErr.Reason {
		case verify.TxGroupErrorReasonNotWellFormed:
			transactionMessagesTxnNotWellFormed.Inc(nil)
		case verify.TxGroupErrorReasonInvalidFee:
			transactionMessagesTxGroupInvalidFee.Inc(nil)
		case verify.TxGroupErrorReasonHasNoSig:
			fallthrough
		case verify.TxGroupErrorReasonSigNotWellFormed:
			transactionMessagesTxnSigNotWellFormed.Inc(nil)
		case verify.TxGroupErrorReasonMsigNotWellFormed:
			transactionMessagesTxnMsigNotWellFormed.Inc(nil)
		case verify.TxGroupErrorReasonLogicSigFailed:
			transactionMessagesTxnLogicSig.Inc(nil)
		default:
			transactionMessagesBacklogErr.Inc(nil)
		}
	} else {
		transactionMessagesBacklogErr.Inc(nil)
	}
}

func (handler *TxHandler) checkReportErrors(err error) {
	switch err := err.(type) {
	case *ledgercore.TxnNotWellFormedError:
		transactionMessageTxPoolCheckCounter.Add(txPoolRememberTagTxnNotWellFormed, 1)
		return
	case *transactions.TxnDeadError:
		if err.Early {
			transactionMessageTxPoolCheckCounter.Add(txPoolRememberTagTxnEarly, 1)
		} else {
			transactionMessageTxPoolCheckCounter.Add(txPoolRememberTagTxnDead, 1)
		}
		return
	case *ledgercore.TransactionInLedgerError:
		if err.InBlockEvaluator {
			transactionMessageTxPoolCheckCounter.Add(txPoolRememberTagTxIDEval, 1)
		} else {
			transactionMessageTxPoolCheckCounter.Add(txPoolRememberTagTxID, 1)
		}
		return
	case *ledgercore.LeaseInLedgerError:
		if err.InBlockEvaluator {
			transactionMessageTxPoolCheckCounter.Add(txPoolRememberTagLeaseEval, 1)
		} else {
			transactionMessageTxPoolCheckCounter.Add(txPoolRememberTagLease, 1)
		}
		return
	case *ledgercore.TxGroupMalformedError:
		switch err.Reason {
		case ledgercore.TxGroupMalformedErrorReasonExceedMaxSize:
			transactionMessageTxPoolCheckCounter.Add(txPoolRememberTagTooLarge, 1)
		default:
			transactionMessageTxPoolCheckCounter.Add(txPoolRememberTagGroupID, 1)
		}
		return
	}

	transactionMessageTxPoolCheckCounter.Add(txPoolRememberTagEvalGeneric, 1)
}

func (handler *TxHandler) rememberReportErrors(err error) {
	if errors.Is(err, pools.ErrPendingQueueReachedMaxCap) {
		transactionMessageTxPoolRememberCounter.Add(txPoolRememberTagCap, 1)
		return
	}

	if errors.Is(err, pools.ErrNoPendingBlockEvaluator) {
		transactionMessageTxPoolRememberCounter.Add(txPoolRememberPendingEval, 1)
		return
	}

	if errors.Is(err, ledgercore.ErrNoSpace) {
		transactionMessageTxPoolRememberCounter.Add(txPoolRememberTagNoSpace, 1)
		return
	}

	// it is possible to call errors.As but it requires additional allocations
	// instead, unwrap and type assert.
	underlyingErr := errors.Unwrap(err)
	if underlyingErr == nil {
		// something went wrong
		return
	}

	switch err := underlyingErr.(type) {
	case *pools.ErrTxPoolFeeError:
		transactionMessageTxPoolRememberCounter.Add(txPoolRememberTagFee, 1)
		return
	case *transactions.TxnDeadError:
		if err.Early {
			transactionMessageTxPoolRememberCounter.Add(txPoolRememberTagTxnEarly, 1)
		} else {
			transactionMessageTxPoolRememberCounter.Add(txPoolRememberTagTxnDead, 1)
		}
		return
	case *ledgercore.TransactionInLedgerError:
		if err.InBlockEvaluator {
			transactionMessageTxPoolRememberCounter.Add(txPoolRememberTagTxIDEval, 1)
		} else {
			transactionMessageTxPoolRememberCounter.Add(txPoolRememberTagTxID, 1)
		}
		return
	case *ledgercore.LeaseInLedgerError:
		if err.InBlockEvaluator {
			transactionMessageTxPoolRememberCounter.Add(txPoolRememberTagLeaseEval, 1)
		} else {
			transactionMessageTxPoolRememberCounter.Add(txPoolRememberTagLease, 1)
		}
		return
	case *ledgercore.TxGroupMalformedError:
		switch err.Reason {
		case ledgercore.TxGroupMalformedErrorReasonExceedMaxSize:
			transactionMessageTxPoolRememberCounter.Add(txPoolRememberTagTooLarge, 1)
		default:
			transactionMessageTxPoolRememberCounter.Add(txPoolRememberTagGroupID, 1)
		}
		return
	}

	transactionMessageTxPoolRememberCounter.Add(txPoolRememberTagEvalGeneric, 1)
}

func (handler *TxHandler) postProcessCheckedTxn(wi *txBacklogMsg) {
	if wi.verificationErr != nil {
		// disconnect from peer.
		handler.postProcessReportErrors(wi.verificationErr)
		handler.log.Warnf("Received a malformed tx group %v: %v", wi.unverifiedTxGroup, wi.verificationErr)
		handler.net.Disconnect(wi.rawmsg.Sender)
		return
	}

	// we've processed this message, so increase the counter.
	transactionMessagesHandled.Inc(nil)

	// at this point, we've verified the transaction, so we can safely treat the transaction as a verified transaction.
	verifiedTxGroup := wi.unverifiedTxGroup

	// save the transaction, if it has high enough fee and not already in the cache
	err := handler.txPool.Remember(verifiedTxGroup)
	if err != nil {
		handler.rememberReportErrors(err)
		handler.log.Debugf("could not remember tx: %v", err)
		return
	}

	transactionMessagesRemember.Inc(nil)

	// if we remembered without any error ( i.e. txpool wasn't full ), then we should pin these transactions.
	err = handler.ledger.VerifiedTransactionCache().Pin(verifiedTxGroup)
	if err != nil {
		handler.log.Infof("unable to pin transaction: %v", err)
	}

	// TODO: at this point, we really really have the Txid and we can mark it done from the Advertised pool. We could go ahead and add it to the Txid cache that lives in front of the pool.

	if handler.relayMessages {
		err = TxnBroadcast(handler.ctx, handler.net, verifiedTxGroup, wi.rawmsg.Sender)
		if err != nil {
			handler.log.Infof("txn relay err: %v", err)
		}
	}
}

const peerTxn2Key = "tx3"

func parseVersion(version string) ([]int, error) {
	parts := strings.Split(version, ".")
	vi := make([]int, len(parts))
	for i, ps := range parts {
		xi, err := strconv.ParseInt(ps, 10, 32)
		if err != nil {
			return nil, err
		}
		vi[i] = int(xi)
	}
	return vi, nil
}

func versionGreaterEqual(a, b []int) bool {
	for i, av := range a {
		if i >= len(b) {
			return true
		}
		if b[i] < av {
			return true
		}
		if b[i] > av {
			return false
		}
	}
	return len(a) == len(b)
}

type tx3Data struct {
	enabled bool
}

var txRequestVersion = []int{3, 0}

// tx3Check determines if a peer is version 3 and does the tx-request protocol.
// The result is cached in peer data.
func tx3Check(net network.GossipNode, npeer network.Peer) (out *tx3Data) {
	txpd := net.GetPeerData(npeer, peerTxn2Key)
	if txpd != nil {
		out, ok := txpd.(*tx3Data)
		if ok {
			return out
		}
	}
	peer, ok := npeer.(network.UnicastPeer)
	if ok {
		pv, err := parseVersion(peer.Version())
		if err == nil && versionGreaterEqual(pv, txRequestVersion) {
			out = &tx3Data{enabled: true}
			net.SetPeerData(npeer, peerTxn2Key, out)
			return out
		}
	} else {
		logging.Base().Infof("peer %p is not UnicastPeer (this should never happen)", peer)
	}
	out = &tx3Data{enabled: false}
	net.SetPeerData(npeer, peerTxn2Key, out)
	return out
}

// TxnBroadcast sends a transaction group to all peers (except sender we got it from).
// TxnBroadcast does protocol things more clever than just sending the txn group, but gets it done in the end.
func TxnBroadcast(ctx context.Context, net network.GossipNode, verifiedTxGroup []transactions.SignedTxn, sender network.Peer) (err error) {
	peers := net.GetPeers(network.PeersConnectedOut, network.PeersConnectedIn)
	logging.Base().Infof("txHandler TxnBroadcast, sender=%p, %d peeers", sender, len(peers))
	var blob []byte
	var txid []byte
	for _, npeer := range peers {
		if npeer == sender {
			continue
		}
		peer, ok := npeer.(network.UnicastPeer)
		if !ok {
			logging.Base().Info("peer is not UnicastPeer (this should never happen)")
			continue
		}
		txpd := tx3Check(net, npeer)
		if txpd.enabled {
			// tx3 protocol
			// avertise the txid, but don't send full txn data yet
			if txid == nil {
				for i := range verifiedTxGroup {
					id := verifiedTxGroup[i].ID()
					logging.Base().Infof("send Ta %s", id.String())
					txid = append(txid, (id[:])...)
				}
			}
			err = peer.Unicast(ctx, txid, protocol.TxnAdvertiseTag)
		} else {
			// not a tx3 protocol client, broadcast txn
			if blob == nil {
				// We reencode here instead of using rawmsg.Data to avoid broadcasting non-canonical encodings
				blob = reencode(verifiedTxGroup)
			}
			err = peer.Unicast(ctx, blob, protocol.TxnTag)
			logging.Base().Info("sent TX")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (handler *TxHandler) deleteFromCaches(msgKey *crypto.Digest, canonicalKey *crypto.Digest) {
	if handler.cacheConfig.enableFilteringCanonical && canonicalKey != nil {
		handler.txCanonicalCache.Delete(canonicalKey)
	}

	if handler.cacheConfig.enableFilteringRawMsg && msgKey != nil {
		handler.msgCache.DeleteByKey(msgKey)
	}
}

// dedupCanonical checks if the transaction group has been seen before after reencoding to canonical representation.
// returns a key used for insertion if the group was not found.
func (handler *TxHandler) dedupCanonical(ntx int, unverifiedTxGroup []transactions.SignedTxn, consumed int) (key *crypto.Digest, isDup bool) {
	// consider situations where someone want to censor transactions A
	// 1. Txn A is not part of a group => txn A with a valid signature is OK
	// Censorship attempts are:
	//  - txn A with an invalid signature => cache/dedup canonical txn with its signature
	//  - txn A with a valid/invalid signature and part of a valid or invalid group => cache/dedup the entire group
	//
	// 2. Txn A is part of a group => txn A with valid GroupID and signature is OK
	// Censorship attempts are:
	// - txn A with a valid or invalid signature => cache/dedup canonical txn with its signature.
	// - txn A as part of a group => cache/dedup the entire group
	//
	// caching approaches that would not work:
	// - using txid: {A} could be poisoned by {A, B} where B is invalid
	// - using individual txn from a group: {A, Z} could be poisoned by {A, B}, where B is invalid

	var d crypto.Digest
	if ntx == 1 {
		// a single transaction => cache/dedup canonical txn with its signature
		enc := unverifiedTxGroup[0].MarshalMsg(nil)
		d = crypto.Hash(enc)
		if handler.txCanonicalCache.CheckAndPut(&d) {
			return nil, true
		}
	} else {
		// a transaction group => cache/dedup the entire group canonical group
		encodeBuf := make([]byte, 0, unverifiedTxGroup[0].Msgsize()*ntx)
		for i := range unverifiedTxGroup {
			encodeBuf = unverifiedTxGroup[i].MarshalMsg(encodeBuf)
		}
		if len(encodeBuf) != consumed {
			// reallocated, some assumption on size was wrong
			// log and skip
			logging.Base().Warnf("Decoded size %d does not match to encoded %d", consumed, len(encodeBuf))
			return nil, false
		}
		d = crypto.Hash(encodeBuf)
		if handler.txCanonicalCache.CheckAndPut(&d) {
			return nil, true
		}
	}
	return &d, false
}

// processIncomingTxn decodes a transaction group from incoming message and enqueues into the back log for processing.
// processIncomingTxn is the handler for protocol.TxnTag "TX"
// The function also performs some input data pre-validation;
//  - txn groups are cut to MaxTxGroupSize size
//  - message are checked for duplicates
//  - transactions are checked for duplicates

func (handler *TxHandler) processIncomingTxn(rawmsg network.IncomingMessage) network.OutgoingMessage {
	var msgKey *crypto.Digest
	var isDup bool
	if handler.cacheConfig.enableFilteringRawMsg {
		// check for duplicate messages
		// this helps against relaying duplicates
		if msgKey, isDup = handler.msgCache.CheckAndPut(rawmsg.Data); isDup {
			transactionMessagesDupRawMsg.Inc(nil)
			return network.OutgoingMessage{Action: network.Ignore}
		}
	}

	unverifiedTxGroup := make([]transactions.SignedTxn, 1)
	dec := protocol.NewMsgpDecoderBytes(rawmsg.Data)
	ntx := 0
	consumed := 0

	var err error
	var capguard *util.ErlCapacityGuard
	if handler.erl != nil {
		// consume a capacity unit
		capguard, err = handler.erl.ConsumeCapacity(rawmsg.Sender.(util.ErlClient))
		if err != nil {
			handler.erl.EnableCongestionControl()
			// if there is no capacity, it is the same as if we failed to put the item onto the backlog, so report such
			transactionMessagesDroppedFromBacklog.Inc(nil)
			return network.OutgoingMessage{Action: network.Ignore}
		}
		// if the backlog Queue has 50% of its buffer back, turn congestion control off
		if float64(cap(handler.backlogQueue))*0.5 > float64(len(handler.backlogQueue)) {
			handler.erl.DisableCongestionControl()
		}
	}

	for {
		if len(unverifiedTxGroup) == ntx {
			n := make([]transactions.SignedTxn, len(unverifiedTxGroup)*2)
			copy(n, unverifiedTxGroup)
			unverifiedTxGroup = n
		}
		err := dec.Decode(&unverifiedTxGroup[ntx])
		if err != nil {
			if err == io.EOF {
				break
			}
			handler.log.Warnf("Received a non-decodable txn: %v", err)
			return network.OutgoingMessage{Action: network.Disconnect}
		}
		consumed = dec.Consumed()
		ntx++
		if ntx >= config.MaxTxGroupSize {
			// max ever possible group size reached, done reading input.
			if dec.Remaining() > 0 {
				// if something else left in the buffer - this is an error, drop
				transactionMessageTxGroupExcessive.Inc(nil)
				return network.OutgoingMessage{Action: network.Disconnect}
			}
		}
	}
	if ntx == 0 {
		handler.log.Warnf("Received empty tx group")
		return network.OutgoingMessage{Action: network.Disconnect}
	}

	unverifiedTxGroup = unverifiedTxGroup[:ntx]
	// TODO: at this point there should be a non-serialized in-memory field in each Transaction that is the Txid and we can calculated it once at this time.

	if ntx == config.MaxTxGroupSize {
		transactionMessageTxGroupFull.Inc(nil)
	}

	var canonicalKey *crypto.Digest
	if handler.cacheConfig.enableFilteringCanonical {
		if canonicalKey, isDup = handler.dedupCanonical(ntx, unverifiedTxGroup, consumed); isDup {
			transactionMessagesDupCanonical.Inc(nil)
			return network.OutgoingMessage{Action: network.Ignore}
		}
	}

	select {
	case handler.backlogQueue <- &txBacklogMsg{
		rawmsg:                &rawmsg,
		unverifiedTxGroup:     unverifiedTxGroup,
		rawmsgDataHash:        msgKey,
		unverifiedTxGroupHash: canonicalKey,
		capguard:              capguard,
	}:
		txidList := make([]transactions.Txid, len(unverifiedTxGroup))
		for i, stxn := range unverifiedTxGroup {
			txidList[i] = stxn.ID()
		}
		// TODO: this should only mark the request as _probably_ done and re-warm the timeout (like a watchdog timer). Later when the Txid is added to the pool we can call it really-really done.
		handler.txidRequestDone <- txidList
	default:
		// If we failed here we want to increase the
		// corresponding metric. It might suggest that we want
		// to increase the queue size.
		transactionMessagesDroppedFromBacklog.Inc(nil)

		// additionally, remove the txn from duplicate caches to ensure it can be re-submitted
		if canonicalKey != nil {
			handler.txCanonicalCache.Delete(canonicalKey)
		}
		if msgKey != nil {
			handler.msgCache.DeleteByKey(msgKey)
		}
	}

	return network.OutgoingMessage{Action: network.Ignore}
}

// we can be lazy responding to advertise offers
const requestExpiration = time.Millisecond * 900

// processIncomingTxnAdvertise is the handler for protocol.TxnAdvertiseTag "Ta"
func (handler *TxHandler) processIncomingTxnAdvertise(rawmsg network.IncomingMessage) network.OutgoingMessage {
	select {
	case handler.txAdvertiseQueue <- rawmsg:
	// enqueued
	default:
		txAdvertiseDrops.Inc(nil)
	}
	return network.OutgoingMessage{}
}

func (handler *TxHandler) processIncomingTxnAdvertiseInner(rawmsg network.IncomingMessage, txidPCache map[transactions.Txid]bool) {
	var request []byte
	var txid transactions.Txid
	peer, ok := rawmsg.Sender.(network.UnicastPeer)
	if !ok {
		handler.log.Errorf("Ta Sender not UnicastPeer")
		txAdvertiseErr.Inc(nil)
		return
	}
	numids := len(rawmsg.Data) / len(txid)
	if numids*len(txid) != len(rawmsg.Data) {
		handler.log.Warnf("got txid advertisement len %d", len(rawmsg.Data))
		txAdvertiseErr.Inc(nil)
		return
	}
	now := time.Now()
	for i := 0; i < numids; i++ {
		copy(txid[:], rawmsg.Data[len(txid)*i:])
		req, ok := handler.txRequests.getByTxid(txid)
		if ok {
			// already have it in active requests
			req.advertisedBy = append(req.advertisedBy, rawmsg.Sender)
			if now.Sub(req.requestedAt) < requestExpiration {
				// no new request
				txAdvertiseProg.Inc(nil)
				continue
			}
			req.requestedAt = now
			heap.Fix(&handler.txRequests, req.heapPos)
		} else {
			found := txidPCache[txid]
			if found {
				// we already have it, nothing to do
				txAdvertisePCache.Inc(nil)
				continue
			}
			_, _, found = handler.txPool.Lookup(txid)
			if found {
				// we already have it, nothing to do
				txAdvertisePool.Inc(nil)
				txidPCache[txid] = true
				continue
			}
			req = new(requestedTxn)
			req.txid = txid
			req.requestedAt = now
			handler.txRequests.add(req)
			req.advertisedBy = append(req.advertisedBy, rawmsg.Sender)
		}
		req.requestedFrom = append(req.requestedFrom, rawmsg.Sender)
		request = append(request, (txid[:])...)
	}
	if len(request) != 0 {
		txRequest.Inc(nil)
		err := peer.Unicast(handler.ctx, request, protocol.TxnRequestTag)
		if err != nil {
			handler.log.Errorf("Ta req err, %v", err)
		}
	}
}

// retryHandler thread retries txn requests that waited too long
// watches heap of requstedTxn inside TxHandler.txRequests heap sorted on (requestedAt time.Time)
func (handler *TxHandler) retryHandler() {
	ticker := time.NewTicker(200 * time.Millisecond)
	var prevRound uint64
	// txidPresenceCache is a local unlocked cache of whether we've seen a txid in txPool (which takes two mutexes to check); replace on block rollover because lots of txPool changes then
	txidPresenceCache := make(map[transactions.Txid]bool)
	defer handler.backlogWg.Done()
	defer ticker.Stop()
	for {
		select {
		case <-handler.ctx.Done():
			return
		case rawmsg := <-handler.txAdvertiseQueue:
			opr := atomic.LoadUint64(&handler.prevRound)
			if opr != prevRound {
				prevRound = opr
				txidPresenceCache = make(map[transactions.Txid]bool)
			}
			handler.processIncomingTxnAdvertiseInner(rawmsg, txidPresenceCache)
		case txidList := <-handler.txidRequestDone:
			for _, txid := range txidList {
				handler.txRequests.popByTxid(txid)
			}
		case now := <-ticker.C:
			handler.retryHandlerTick(now)
		}
	}
}

// retryHandlerTick gets a list of requests to send then Unicast sends them
func (handler *TxHandler) retryHandlerTick(now time.Time) {
	toRequest := handler.retryHandlerTickRequestList(now)
	if len(toRequest) == 0 {
		return
	}
	for npeer, request := range toRequest {
		peer, ok := npeer.(network.UnicastPeer)
		if !ok {
			handler.log.Errorf("Ta Sender not UnicastPeer")
			continue
		}
		txRequestRetry.Inc(nil)
		err := peer.Unicast(handler.ctx, request, protocol.TxnRequestTag)
		if err != nil {
			handler.log.Errorf("Ta req err, %v", err)
		}
	}
}

// retryHandlerTickRequestList holds a lock but just long enough to make a list of slow fetches to do later
func (handler *TxHandler) retryHandlerTickRequestList(now time.Time) (toRequest map[network.Peer][]byte) {
	if len(handler.txRequests.ar) == 0 {
		return
	}
	timeout := now.Add(-1 * requestExpiration)
	req := handler.txRequests.ar[0]
	for req.requestedAt.Before(timeout) {
		var nextSource network.Peer
		// find a peer that has advertised it who we haven't asked yet
		for _, source := range req.advertisedBy {
			alreadyAsked := false
			for _, prevReq := range req.requestedFrom {
				// skip source we already asked
				if prevReq == source {
					alreadyAsked = true
					break
				}
			}
			if !alreadyAsked {
				nextSource = source
				break
			}
		}
		if nextSource != nil {
			if toRequest == nil {
				toRequest = make(map[network.Peer][]byte)
			}
			toRequest[nextSource] = append(toRequest[nextSource], (req.txid[:])...)
			req.requestedAt = now
			req.requestedFrom = append(req.requestedFrom, nextSource)
			heap.Fix(&handler.txRequests, 0)
		} else {
			// no next source, nothing to do, forget this request, a new advertisement will trigger a new request
			heap.Pop(&handler.txRequests)
			delete(handler.txRequests.byTxid, req.txid)
		}
		if len(handler.txRequests.ar) == 0 {
			break
		}
		req = handler.txRequests.ar[0]
	}
	return
}

// getByTxid looks up a transaction first in the pool, then in the previous block
func (handler *TxHandler) getByTxid(txid transactions.Txid) (tx transactions.SignedTxn, found bool) {
	tx, _, found = handler.txPool.Lookup(txid)
	if found {
		handler.log.Infof("Tr p %s", txid.String())
		return tx, found
	}
	ptany := handler.prevTxns.Load()
	if ptany == nil {
		handler.log.Infof("Tr np MISSING %s", txid.String())
	}
	prevTxns := ptany.(map[transactions.Txid]transactions.SignedTxn)
	tx, found = prevTxns[txid]
	if !found {
		handler.log.Infof("Tr MISSING %s", txid.String())
	}
	return tx, found
}

// processIncomingTxnRequest is the handler for protocol.TxnRequestTag "Tr"
func (handler *TxHandler) processIncomingTxnRequest(rawmsg network.IncomingMessage) network.OutgoingMessage {
	peer, ok := rawmsg.Sender.(network.UnicastPeer)
	if !ok {
		handler.log.Errorf("Tr Sender not UnicastPeer")
		txRequestInErr.Inc(nil)
		return network.OutgoingMessage{}
	}
	var txid transactions.Txid
	numids := len(rawmsg.Data) / len(txid)
	if numids*len(txid) != len(rawmsg.Data) {
		handler.log.Warnf("got Tr len %d", len(rawmsg.Data))
		txRequestInErr.Inc(nil)
		return network.OutgoingMessage{Action: network.Disconnect}
	}
	response := make([]transactions.SignedTxn, numids)
	numFound := 0
	for i := 0; i < numids; i++ {
		copy(txid[:], rawmsg.Data[len(txid)*i:])
		tx, found := handler.getByTxid(txid)
		if found {
			response[i] = tx
			numFound++
		}
	}
	if numFound != 0 {
		err := peer.Unicast(handler.ctx, reencode(response), protocol.TxnTag)
		if err != nil {
			handler.log.Errorf("Tr res err, %v", err)
		}
		txRequestInOk.Inc(nil)
	} else {
		// Maybe add NACK message to protocol so they can ask another node?
		// But really, this should never happen. We advertised it. We should have it.
		//handler.log.Error("request for txid we don't have: %s", txid.String())
		txRequestInMiss.Inc(nil)
	}
	return network.OutgoingMessage{}
}

// checkAlreadyCommitted test to see if the given transaction ( in the txBacklogMsg ) was already committed, and
// whether it would qualify as a candidate for the transaction pool.
//
// Note that this also checks the consistency of the transaction's group hash,
// which is required for safe transaction signature caching behavior.
func (handler *TxHandler) checkAlreadyCommitted(tx *txBacklogMsg) (processingDone bool) {
	if handler.log.IsLevelEnabled(logging.Debug) {
		txids := make([]transactions.Txid, len(tx.unverifiedTxGroup))
		for i := range tx.unverifiedTxGroup {
			txids[i] = tx.unverifiedTxGroup[i].ID()
		}
		handler.log.Debugf("got a tx group with IDs %v", txids)
	}

	// do a quick test to check that this transaction could potentially be committed, to reject dup pending transactions
	err := handler.txPool.Test(tx.unverifiedTxGroup)
	if err != nil {
		handler.checkReportErrors(err)
		handler.log.Debugf("txPool rejected transaction: %v", err)
		return true
	}
	return false
}

func (handler *TxHandler) processDecoded(unverifiedTxGroup []transactions.SignedTxn) (outmsg network.OutgoingMessage, processingDone bool) {
	tx := &txBacklogMsg{
		unverifiedTxGroup: unverifiedTxGroup,
	}
	transactionGroupTxSyncHandled.Inc(nil)

	if handler.checkAlreadyCommitted(tx) {
		transactionGroupTxSyncAlreadyCommitted.Inc(nil)
		return network.OutgoingMessage{}, true
	}

	// build the transaction verification context
	latest := handler.ledger.Latest()
	latestHdr, err := handler.ledger.BlockHdr(latest)
	if err != nil {
		handler.log.Warnf("Could not get header for previous block %v: %v", latest, err)
		return network.OutgoingMessage{}, true
	}

	unverifiedTxnGroups := bookkeeping.SignedTxnsToGroups(unverifiedTxGroup)
	err = verify.PaysetGroups(context.Background(), unverifiedTxnGroups, latestHdr, handler.txVerificationPool, handler.ledger.VerifiedTransactionCache(), handler.ledger)
	if err != nil {
		// transaction is invalid
		handler.log.Warnf("One or more transactions were malformed: %v", err)
		return network.OutgoingMessage{Action: network.Disconnect}, true
	}

	// at this point, we've verified the transaction group,
	// so we can safely treat the transaction as a verified transaction.
	verifiedTxGroup := unverifiedTxGroup

	// save the transaction, if it has high enough fee and not already in the cache
	err = handler.txPool.Remember(verifiedTxGroup)
	if err != nil {
		handler.log.Debugf("could not remember tx: %v", err)
		return network.OutgoingMessage{}, true
	}

	transactionGroupTxSyncRemember.Inc(nil)

	// if we remembered without any error ( i.e. txpool wasn't full ), then we should pin these transactions.
	err = handler.ledger.VerifiedTransactionCache().Pin(verifiedTxGroup)
	if err != nil {
		handler.log.Warnf("unable to pin transaction: %v", err)
	}

	return network.OutgoingMessage{}, false
}

// SolicitedTxHandler handles messages received through channels other than the gossip network.
// It therefore circumvents the notion of incoming/outgoing messages
type SolicitedTxHandler interface {
	Handle(txgroup []transactions.SignedTxn) error
}

// SolicitedTxHandler converts a transaction handler to a SolicitedTxHandler
func (handler *TxHandler) SolicitedTxHandler() SolicitedTxHandler {
	return &solicitedTxHandler{txHandler: handler}
}

type solicitedTxHandler struct {
	txHandler *TxHandler
}

func (handler *solicitedTxHandler) Handle(txgroup []transactions.SignedTxn) error {
	outmsg, _ := handler.txHandler.processDecoded(txgroup)
	if outmsg.Action == network.Disconnect {
		return fmt.Errorf("invalid transaction")
	}
	return nil
}
