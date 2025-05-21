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

package data

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/config/bounds"
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
	"github.com/algorand/go-deadlock"
)

var transactionMessagesHandled = metrics.MakeCounter(metrics.TransactionMessagesHandled)
var transactionMessagesDroppedFromBacklog = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromBacklog)
var transactionMessagesDroppedFromPool = metrics.MakeCounter(metrics.TransactionMessagesDroppedFromPool)
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
var transactionMessagesAppLimiterDrop = metrics.MakeCounter(metrics.TransactionMessagesAppLimiterDrop)
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
	rawmsg                *network.IncomingMessage      // the raw message from the network
	unverifiedTxGroup     []transactions.SignedTxn      // the unverified ( and signed ) transaction group
	rawmsgDataHash        crypto.Digest                 // hash (or IsZero) of raw message data from the network
	unverifiedTxGroupHash crypto.Digest                 // hash (or IsZero) of the unverifiedTxGroup
	verificationErr       error                         // The verification error generated by the verification function, if any.
	capguard              *util.ErlCapacityGuard        // the structure returned from the elastic rate limiter, to be released when dequeued
	syncCh                chan network.ForwardingPolicy // channel to signal the synchronous mode and its ops completion
}

// TxHandler handles transaction messages
type TxHandler struct {
	txPool                     *pools.TransactionPool
	ledger                     *Ledger
	txVerificationPool         execpool.BacklogPool
	backlogQueue               chan *txBacklogMsg
	backlogCongestionThreshold float64
	postVerificationQueue      chan *verify.VerificationResult
	backlogWg                  sync.WaitGroup
	net                        network.GossipNode
	msgCache                   *txSaltedCache
	txCanonicalCache           *digestCache
	ctx                        context.Context
	ctxCancel                  context.CancelFunc
	streamVerifier             *execpool.StreamToBatch
	streamVerifierChan         chan execpool.InputJob
	streamVerifierDropped      chan *verify.UnverifiedTxnSigJob
	erl                        *util.ElasticRateLimiter
	erlClientMapper            erlClientMapper
	appLimiter                 *appRateLimiter
	appLimiterBacklogThreshold int
	appLimiterCountERLDrops    bool

	// batchVerifier provides synchronous verification of transaction groups, used only by pubsub validation in validateIncomingTxMessage.
	batchVerifier verify.TxnGroupBatchSigVerifier
}

// TxHandlerOpts is TxHandler configuration options
type TxHandlerOpts struct {
	TxPool        *pools.TransactionPool
	ExecutionPool execpool.BacklogPool
	Ledger        *Ledger
	Net           network.GossipNode
	Config        config.Local
}

// HybridRelayer is an interface for relaying p2p transactions to WS network
type HybridRelayer interface {
	BridgeP2PToWS(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except network.Peer) error
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
		ledger:                opts.Ledger,
		txVerificationPool:    opts.ExecutionPool,
		backlogQueue:          make(chan *txBacklogMsg, txBacklogSize),
		postVerificationQueue: make(chan *verify.VerificationResult, txBacklogSize),
		net:                   opts.Net,
		streamVerifierChan:    make(chan execpool.InputJob),
		streamVerifierDropped: make(chan *verify.UnverifiedTxnSigJob),
	}

	if opts.Config.TxFilterRawMsgEnabled() {
		handler.msgCache = makeSaltedCache(int(opts.Config.TxIncomingFilterMaxSize))
	}
	if opts.Config.TxFilterCanonicalEnabled() {
		handler.txCanonicalCache = makeDigestCache(int(opts.Config.TxIncomingFilterMaxSize))
	}

	if opts.Config.EnableTxBacklogRateLimiting || opts.Config.EnableTxBacklogAppRateLimiting {
		if opts.Config.TxBacklogRateLimitingCongestionPct > 100 || opts.Config.TxBacklogRateLimitingCongestionPct < 0 {
			return nil, fmt.Errorf("invalid value for TxBacklogRateLimitingCongestionPct: %d", opts.Config.TxBacklogRateLimitingCongestionPct)
		}
		if opts.Config.EnableTxBacklogAppRateLimiting && opts.Config.TxBacklogAppTxRateLimiterMaxSize == 0 {
			return nil, fmt.Errorf("invalid value for TxBacklogAppTxRateLimiterMaxSize: %d. App rate limiter enabled with zero size", opts.Config.TxBacklogAppTxRateLimiterMaxSize)
		}
		handler.backlogCongestionThreshold = float64(opts.Config.TxBacklogRateLimitingCongestionPct) / 100
		if opts.Config.EnableTxBacklogRateLimiting {
			handler.erl = util.NewElasticRateLimiter(
				txBacklogSize,
				opts.Config.TxBacklogReservedCapacityPerPeer,
				time.Duration(opts.Config.TxBacklogServiceRateWindowSeconds)*time.Second,
				txBacklogDroppedCongestionManagement,
			)
			handler.erlClientMapper = erlClientMapper{
				mapping:    make(map[string]*erlIPClient),
				maxClients: opts.Config.MaxConnectionsPerIP,
			}
		}
		if opts.Config.EnableTxBacklogAppRateLimiting {
			handler.appLimiter = makeAppRateLimiter(
				opts.Config.TxBacklogAppTxRateLimiterMaxSize,
				uint64(opts.Config.TxBacklogAppTxPerSecondRate),
				time.Duration(opts.Config.TxBacklogServiceRateWindowSeconds)*time.Second,
			)
			// set appLimiter triggering threshold at 50% of the base backlog size
			handler.appLimiterBacklogThreshold = int(float64(opts.Config.TxBacklogSize) * float64(opts.Config.TxBacklogRateLimitingCongestionPct) / 100)
			handler.appLimiterCountERLDrops = opts.Config.TxBacklogAppRateLimitingCountERLDrops
		}
	}

	// prepare the batch processor for pubsub synchronous verification
	var err error
	handler.batchVerifier, err = verify.MakeSigVerifier(handler.ledger, handler.ledger.VerifiedTransactionCache())
	if err != nil {
		return nil, err
	}

	// prepare the transaction stream verifier
	txnElementProcessor, err := verify.MakeSigVerifyJobProcessor(handler.ledger, handler.ledger.VerifiedTransactionCache(),
		handler.postVerificationQueue, handler.streamVerifierDropped)
	if err != nil {
		return nil, err
	}
	handler.streamVerifier = execpool.MakeStreamToBatch(handler.streamVerifierChan, handler.txVerificationPool, txnElementProcessor)
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

// Start enables the processing of incoming messages at the transaction handler
func (handler *TxHandler) Start() {
	handler.ctx, handler.ctxCancel = context.WithCancel(context.Background())
	if handler.msgCache != nil {
		handler.msgCache.Start(handler.ctx, 60*time.Second)
	}
	// wsNetwork handler
	handler.net.RegisterHandlers([]network.TaggedMessageHandler{
		{Tag: protocol.TxnTag, MessageHandler: network.HandlerFunc(handler.processIncomingTxn)},
	})

	// libp2p pubsub validator and handler abstracted as TaggedMessageProcessor
	handler.net.RegisterValidatorHandlers([]network.TaggedMessageValidatorHandler{
		{Tag: protocol.TxnTag, MessageHandler: network.ValidateHandleFunc(handler.validateIncomingTxMessage)},
	})

	handler.backlogWg.Add(2)
	go handler.backlogWorker()
	go handler.backlogGaugeThread()
	handler.streamVerifier.Start(handler.ctx)
	if handler.erl != nil {
		handler.erl.Start()
	}
}

// Stop suspends the processing of incoming messages at the transaction handler
func (handler *TxHandler) Stop() {
	logging.Base().Debug("transaction handler is stopping")
	defer logging.Base().Debug("transaction handler is stopping")

	handler.ctxCancel()
	if handler.erl != nil {
		handler.erl.Stop()
	}
	handler.backlogWg.Wait()
	handler.streamVerifier.WaitForStop()
	if handler.msgCache != nil {
		handler.msgCache.WaitForStop()
	}
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
			transactionMessagesBacklogSizeGauge.Set(uint64(len(handler.backlogQueue)))
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
				// if in synchronous mode, signal the completion of the operation
				if wi.syncCh != nil {
					wi.syncCh <- network.Ignore
				}
				continue
			}
			// handler.streamVerifierChan does not receive if ctx is cancelled
			select {
			case handler.streamVerifierChan <- &verify.UnverifiedTxnSigJob{TxnGroup: wi.unverifiedTxGroup, BacklogMessage: wi}:
			case <-handler.ctx.Done():
				transactionMessagesDroppedFromBacklog.Inc(nil)
				// if in synchronous mode, signal the completion of the operation
				if wi.syncCh != nil {
					wi.syncCh <- network.Ignore
				}
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
	case *bookkeeping.TxnDeadError:
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
	case *bookkeeping.TxnDeadError:
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
		logging.Base().Warnf("Received a malformed tx group %v: %v", wi.unverifiedTxGroup, wi.verificationErr)
		// if in synchronous mode, signal the completion of the operation
		if wi.syncCh != nil {
			wi.syncCh <- network.Disconnect
			return
		}
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
		logging.Base().Debugf("could not remember tx: %v", err)
		// if in synchronous mode, signal the completion of the operation
		if wi.syncCh != nil {
			wi.syncCh <- network.Ignore
		}
		return
	}

	transactionMessagesRemember.Inc(nil)

	// if we remembered without any error ( i.e. txpool wasn't full ), then we should pin these transactions.
	err = handler.ledger.VerifiedTransactionCache().Pin(verifiedTxGroup)
	if err != nil {
		logging.Base().Infof("unable to pin transaction: %v", err)
	}
	// if in synchronous mode, signal the completion of the operation
	if wi.syncCh != nil {
		wi.syncCh <- network.Accept
		return
	}

	// We reencode here instead of using rawmsg.Data to avoid broadcasting non-canonical encodings
	handler.net.Relay(handler.ctx, protocol.TxnTag, reencode(verifiedTxGroup), false, wi.rawmsg.Sender)
}

func (handler *TxHandler) deleteFromCaches(msgKey crypto.Digest, canonicalKey crypto.Digest) {
	if handler.txCanonicalCache != nil && !canonicalKey.IsZero() {
		handler.txCanonicalCache.Delete(canonicalKey)
	}

	if handler.msgCache != nil && !msgKey.IsZero() {
		handler.msgCache.DeleteByKey(msgKey)
	}
}

// dedupCanonical checks if the transaction group has been seen before after reencoding to canonical representation.
// returns a key used for insertion if the group was not found.
func (handler *TxHandler) dedupCanonical(unverifiedTxGroup []transactions.SignedTxn, consumed int) (key crypto.Digest, reencoded []byte, isDup bool) {
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
	var reencodedBuf []byte
	ntx := len(unverifiedTxGroup)
	if ntx == 1 {
		// a single transaction => cache/dedup canonical txn with its signature
		enc := unverifiedTxGroup[0].MarshalMsg(nil)
		d = crypto.Hash(enc)
		if handler.txCanonicalCache.CheckAndPut(d) {
			return crypto.Digest{}, nil, true
		}
		reencodedBuf = enc
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
			return crypto.Digest{}, nil, false
		}
		d = crypto.Hash(encodeBuf)
		if handler.txCanonicalCache.CheckAndPut(d) {
			return crypto.Digest{}, nil, true
		}
		reencodedBuf = encodeBuf
	}
	return d, reencodedBuf, false
}

// incomingMsgDupCheck runs the duplicate check on a raw incoming message.
// Returns:
// - the key used for insertion if the message was not found in the cache
// - a boolean indicating if the message was a duplicate
func (handler *TxHandler) incomingMsgDupCheck(data []byte) (crypto.Digest, bool) {
	var msgKey crypto.Digest
	var isDup bool
	if handler.msgCache != nil {
		// check for duplicate messages
		// this helps against relaying duplicates
		if msgKey, isDup = handler.msgCache.CheckAndPut(data); isDup {
			transactionMessagesDupRawMsg.Inc(nil)
			return msgKey, true
		}
	}
	return msgKey, false
}

// erlClientMapper handles erlIPClient creation from erlClient
// in order to map multiple clients to a single IP address.
// Then that meta erlIPClient is supposed to be supplied to ERL
type erlClientMapper struct {
	m          deadlock.RWMutex
	mapping    map[string]*erlIPClient
	maxClients int
}

// getClient returns erlIPClient for a given sender
func (mp *erlClientMapper) getClient(sender network.DisconnectableAddressablePeer) util.ErlClient {
	addr := string(sender.RoutingAddr())
	ec := sender.(util.ErlClient)

	// check if the client is already known
	// typically one client sends lots of messages so more much more reads than writes.
	// handle with a quick read lock, and if not found, create a new one with a write lock
	mp.m.RLock()
	ipClient, has := mp.mapping[addr]
	mp.m.RUnlock()

	if !has {
		ipClient = mp.getClientByAddr(addr)
	}

	ipClient.register(ec)
	return ipClient
}

// getClientByAddr is internal helper to get or create a new erlIPClient
// with write lock held
func (mp *erlClientMapper) getClientByAddr(addr string) *erlIPClient {
	mp.m.Lock()
	defer mp.m.Unlock()

	ipClient, has := mp.mapping[addr]
	if !has {
		ipClient = &erlIPClient{
			clients: make(map[util.ErlClient]struct{}, mp.maxClients),
		}
		mp.mapping[addr] = ipClient
	}
	return ipClient
}

type erlIPClient struct {
	util.ErlClient
	m       deadlock.RWMutex
	clients map[util.ErlClient]struct{}
	closer  func()
}

func (eic *erlIPClient) OnClose(f func()) {
	eic.m.Lock()
	defer eic.m.Unlock()
	eic.closer = f
}

// register registers a new client to the erlIPClient
// by adding a helper closer function to track connection closures
func (eic *erlIPClient) register(ec util.ErlClient) {
	eic.m.Lock()
	defer eic.m.Unlock()
	if _, has := eic.clients[ec]; has {
		// this peer is known => noop
		return
	}
	eic.clients[ec] = struct{}{}

	ec.OnClose(func() {
		eic.connClosed(ec)
	})
}

// connClosed is called when a connection is closed so that
// erlIPClient removes the client from its list of clients
// and calls the closer function if there are no more clients
func (eic *erlIPClient) connClosed(ec util.ErlClient) {
	eic.m.Lock()
	defer eic.m.Unlock()
	delete(eic.clients, ec)
	empty := len(eic.clients) == 0
	// if no elements left, call the closer
	if empty && eic.closer != nil {
		eic.closer()
		eic.closer = nil
	}
}

// incomingMsgErlCheck runs the rate limiting check on a sender.
// Returns:
// - the capacity guard returned by the elastic rate limiter
// - a boolean indicating if the sender is rate limited
func (handler *TxHandler) incomingMsgErlCheck(sender util.ErlClient) (*util.ErlCapacityGuard, bool) {
	congestedERL := float64(cap(handler.backlogQueue))*handler.backlogCongestionThreshold < float64(len(handler.backlogQueue))
	// consume a capacity unit
	// if the elastic rate limiter cannot vend a capacity, the error it returns
	// is sufficient to indicate that we should enable Congestion Control, because
	// an issue in vending capacity indicates the underlying resource (TXBacklog) is full
	capguard, isCMEnabled, err := handler.erl.ConsumeCapacity(sender)
	if err != nil { // did ERL ask to enable congestion control?
		handler.erl.EnableCongestionControl()
		// if there is no capacity, it is the same as if we failed to put the item onto the backlog, so report such
		transactionMessagesDroppedFromBacklog.Inc(nil)
		return capguard, true
	} else if !isCMEnabled && congestedERL { // is CM not currently enabled, but queue is congested?
		handler.erl.EnableCongestionControl()
	} else if !congestedERL {
		// if the backlog Queue has 50% of its buffer back, turn congestion control off
		handler.erl.DisableCongestionControl()
	}
	return capguard, false
}

// decodeMsg decodes TX message buffer into transactions.SignedTxn,
// and returns number of bytes consumed from the buffer and a boolean indicating if the message was invalid.
func decodeMsg(data []byte) (unverifiedTxGroup []transactions.SignedTxn, consumed int, invalid bool) {
	unverifiedTxGroup = make([]transactions.SignedTxn, 1)
	dec := protocol.NewMsgpDecoderBytes(data)
	ntx := 0

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
			logging.Base().Warnf("Received a non-decodable txn: %v", err)
			return nil, 0, true
		}
		consumed = dec.Consumed()
		ntx++
		if ntx >= bounds.MaxTxGroupSize {
			// max ever possible group size reached, done reading input.
			if dec.Remaining() > 0 {
				// if something else left in the buffer - this is an error, drop
				transactionMessageTxGroupExcessive.Inc(nil)
				return nil, 0, true
			}
		}
	}
	if ntx == 0 {
		logging.Base().Warnf("Received empty tx group")
		return nil, 0, true
	}

	unverifiedTxGroup = unverifiedTxGroup[:ntx]

	if ntx == bounds.MaxTxGroupSize {
		transactionMessageTxGroupFull.Inc(nil)
	}

	return unverifiedTxGroup, consumed, false
}

// incomingTxGroupCanonicalDedup checks if the incoming transaction group has been seen before after reencoding to canonical representation.
// It also return canonical representation of the transaction group allowing the caller to compare it with the input.
func (handler *TxHandler) incomingTxGroupCanonicalDedup(unverifiedTxGroup []transactions.SignedTxn, encodedExpectedSize int) (crypto.Digest, []byte, bool) {
	var canonicalKey crypto.Digest
	var reencoded []byte
	if handler.txCanonicalCache != nil {
		var isDup bool
		if canonicalKey, reencoded, isDup = handler.dedupCanonical(unverifiedTxGroup, encodedExpectedSize); isDup {
			transactionMessagesDupCanonical.Inc(nil)
			return crypto.Digest{}, nil, true
		}
	}
	return canonicalKey, reencoded, false
}

// incomingTxGroupAppRateLimit checks if the sender is rate limited by the per-application rate limiter.
func (handler *TxHandler) incomingTxGroupAppRateLimit(unverifiedTxGroup []transactions.SignedTxn, sender network.DisconnectableAddressablePeer) bool {
	// rate limit per application in a group. Limiting any app in a group drops the entire message.
	if handler.appLimiter != nil {
		congestedARL := len(handler.backlogQueue) > handler.appLimiterBacklogThreshold
		if congestedARL && handler.appLimiter.shouldDrop(unverifiedTxGroup, sender.RoutingAddr()) {
			transactionMessagesAppLimiterDrop.Inc(nil)
			return true
		}
	}
	return false
}

// processIncomingTxn decodes a transaction group from incoming message and enqueues into the back log for processing.
// The function also performs some input data pre-validation;
//   - txn groups are cut to MaxTxGroupSize size
//   - message are checked for duplicates
//   - transactions are checked for duplicates
func (handler *TxHandler) processIncomingTxn(rawmsg network.IncomingMessage) network.OutgoingMessage {
	msgKey, shouldDrop := handler.incomingMsgDupCheck(rawmsg.Data)
	if shouldDrop {
		return network.OutgoingMessage{Action: network.Ignore}
	}

	var capguard *util.ErlCapacityGuard
	if handler.erl != nil {
		client := handler.erlClientMapper.getClient(rawmsg.Sender)
		capguard, shouldDrop = handler.incomingMsgErlCheck(client)
	}
	accepted := false
	defer func() {
		// if we failed to put the item onto the backlog, we should release the capacity if any
		if !accepted && capguard != nil {
			if capErr := capguard.Release(); capErr != nil {
				logging.Base().Warnf("processIncomingTxn: failed to release capacity to ElasticRateLimiter: %v", capErr)
			}
		}
	}()

	if shouldDrop {
		if handler.appLimiterCountERLDrops {
			// decode and let ARL count this txgroup, even though ERL is dropping it
			if unverifiedTxGroup, _, invalid := decodeMsg(rawmsg.Data); !invalid {
				handler.incomingTxGroupAppRateLimit(unverifiedTxGroup, rawmsg.Sender)
			}
		}
		// this TX message was rate-limited by ERL
		return network.OutgoingMessage{Action: network.Ignore}
	}

	unverifiedTxGroup, consumed, invalid := decodeMsg(rawmsg.Data)
	if invalid {
		// invalid encoding or exceeding txgroup, disconnect from this peer
		return network.OutgoingMessage{Action: network.Disconnect}
	}

	canonicalKey, _, drop := handler.incomingTxGroupCanonicalDedup(unverifiedTxGroup, consumed)
	if drop {
		// this re-serialized txgroup was detected as a duplicate by the canonical message cache,
		// or it was rate-limited by the per-app rate limiter
		return network.OutgoingMessage{Action: network.Ignore}
	}

	if handler.incomingTxGroupAppRateLimit(unverifiedTxGroup, rawmsg.Sender) {
		return network.OutgoingMessage{Action: network.Ignore}
	}

	select {
	case handler.backlogQueue <- &txBacklogMsg{
		rawmsg:                &rawmsg,
		unverifiedTxGroup:     unverifiedTxGroup,
		rawmsgDataHash:        msgKey,
		unverifiedTxGroupHash: canonicalKey,
		capguard:              capguard,
	}:
		accepted = true
	default:
		// if we failed here we want to increase the corresponding metric. It might suggest that we
		// want to increase the queue size.
		transactionMessagesDroppedFromBacklog.Inc(nil)

		// additionally, remove the txn from duplicate caches to ensure it can be re-submitted
		handler.deleteFromCaches(msgKey, canonicalKey)
	}

	return network.OutgoingMessage{Action: network.Ignore}
}

// validateIncomingTxMessage is the validator for the MessageProcessor implementation used by P2PNetwork.
func (handler *TxHandler) validateIncomingTxMessage(rawmsg network.IncomingMessage) network.OutgoingMessage {
	unverifiedTxGroup, consumed, invalid := decodeMsg(rawmsg.Data)
	if invalid {
		// invalid encoding or exceeding txgroup, disconnect from this peer
		return network.OutgoingMessage{Action: network.Disconnect}
	}

	canonicalKey, reencoded, drop := handler.incomingTxGroupCanonicalDedup(unverifiedTxGroup, consumed)
	if drop {
		return network.OutgoingMessage{Action: network.Ignore}
	}

	if handler.incomingTxGroupAppRateLimit(unverifiedTxGroup, rawmsg.Sender) {
		return network.OutgoingMessage{Action: network.Ignore}
	}

	if reencoded == nil {
		reencoded = reencode(unverifiedTxGroup)
	}

	if !bytes.Equal(rawmsg.Data, reencoded) {
		// reject non-canonically encoded messages
		return network.OutgoingMessage{Action: network.Disconnect}
	}

	// apply backlog worker logic

	wi := &txBacklogMsg{
		rawmsg:                &rawmsg,
		unverifiedTxGroup:     unverifiedTxGroup,
		unverifiedTxGroupHash: canonicalKey,
		capguard:              nil,
		syncCh:                make(chan network.ForwardingPolicy, 1),
	}

	var action network.ForwardingPolicy
	select {
	case handler.backlogQueue <- wi:
		action = <-wi.syncCh
	default:
		// if we failed here we want to increase the corresponding metric. It might suggest that we
		// want to increase the queue size.
		transactionMessagesDroppedFromBacklog.Inc(nil)

		// additionally, remove the txn from duplicate caches to ensure it can be re-submitted
		handler.deleteFromCaches(crypto.Digest{}, canonicalKey)

		// queue is full, do not if the message valid or not so ignore
		action = network.Ignore
	}

	if hybridNet, ok := handler.net.(HybridRelayer); ok {
		_ = hybridNet.BridgeP2PToWS(handler.ctx, protocol.TxnTag, reencoded, false, wi.rawmsg.Sender)
	}

	return network.OutgoingMessage{
		Action: action,
	}
}

var errBackLogFullLocal = errors.New("backlog full")

// LocalTransaction is a special shortcut handler for local transactions and intended to be used
// for performance testing and debugging purposes only since it does not have congestion control
// and duplicates detection.
func (handler *TxHandler) LocalTransaction(txgroup []transactions.SignedTxn) error {
	select {
	case handler.backlogQueue <- &txBacklogMsg{
		rawmsg:            &network.IncomingMessage{},
		unverifiedTxGroup: txgroup,
		capguard:          nil,
	}:
	default:
		transactionMessagesDroppedFromBacklog.Inc(nil)
		return errBackLogFullLocal
	}
	return nil
}

// checkAlreadyCommitted test to see if the given transaction ( in the txBacklogMsg ) was already committed, and
// whether it would qualify as a candidate for the transaction pool.
//
// Note that this also checks the consistency of the transaction's group hash,
// which is required for safe transaction signature caching behavior.
func (handler *TxHandler) checkAlreadyCommitted(tx *txBacklogMsg) (processingDone bool) {
	if logging.Base().IsLevelEnabled(logging.Debug) {
		txids := make([]transactions.Txid, len(tx.unverifiedTxGroup))
		for i := range tx.unverifiedTxGroup {
			txids[i] = tx.unverifiedTxGroup[i].ID()
		}
		logging.Base().Debugf("got a tx group with IDs %v", txids)
	}

	// do a quick test to check that this transaction could potentially be committed, to reject dup pending transactions
	err := handler.txPool.Test(tx.unverifiedTxGroup)
	if err != nil {
		handler.checkReportErrors(err)
		logging.Base().Debugf("txPool rejected transaction: %v", err)
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
		logging.Base().Warnf("Could not get header for previous block %v: %v", latest, err)
		return network.OutgoingMessage{}, true
	}

	unverifiedTxnGroups := bookkeeping.SignedTxnsToGroups(unverifiedTxGroup)
	err = verify.PaysetGroups(context.Background(), unverifiedTxnGroups, latestHdr, handler.txVerificationPool, handler.ledger.VerifiedTransactionCache(), handler.ledger)
	if err != nil {
		// transaction is invalid
		logging.Base().Warnf("One or more transactions were malformed: %v", err)
		return network.OutgoingMessage{Action: network.Disconnect}, true
	}

	// at this point, we've verified the transaction group,
	// so we can safely treat the transaction as a verified transaction.
	verifiedTxGroup := unverifiedTxGroup

	// save the transaction, if it has high enough fee and not already in the cache
	err = handler.txPool.Remember(verifiedTxGroup)
	if err != nil {
		logging.Base().Debugf("could not remember tx: %v", err)
		return network.OutgoingMessage{}, true
	}

	transactionGroupTxSyncRemember.Inc(nil)

	// if we remembered without any error ( i.e. txpool wasn't full ), then we should pin these transactions.
	err = handler.ledger.VerifiedTransactionCache().Pin(verifiedTxGroup)
	if err != nil {
		logging.Base().Warnf("unable to pin transaction: %v", err)
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
