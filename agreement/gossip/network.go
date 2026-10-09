// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

// Package gossip adapts the interface of network.GossipNode to
// agreement.Network.
package gossip

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/network/messagetracer"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/metrics"
)

var messagesHandledTotal = metrics.MakeCounter(metrics.AgreementMessagesHandled)
var messagesHandledByType = metrics.NewTagCounter("algod_agreement_handled_{TAG}", "Number of agreement {TAG} messages handled",
	agreementVoteMessageType, agreementProposalMessageType, agreementBundleMessageType)
var messagesDroppedTotal = metrics.MakeCounter(metrics.AgreementMessagesDropped)
var messagesDroppedByType = metrics.NewTagCounter("algod_agreement_dropped_{TAG}", "Number of agreement {TAG} messages dropped",
	agreementVoteMessageType, agreementProposalMessageType, agreementBundleMessageType)

// processValidateMessage instrumentation. Together these let an operator detect
// validator-goroutine leaks (entries > exits over time, or in-flight gauge that
// only grows) and per-action latency outliers.
var validateMessageEntryByType = metrics.NewTagCounter("algod_agreement_validate_entry_{TAG}", "Number of agreement {TAG} messages entering processValidateMessage",
	agreementVoteMessageType, agreementProposalMessageType, agreementBundleMessageType)
var validateMessageExitByType = metrics.NewTagCounter("algod_agreement_validate_exit_{TAG}", "Number of agreement {TAG} messages exiting processValidateMessage",
	agreementVoteMessageType, agreementProposalMessageType, agreementBundleMessageType)
var validateMessageExitByAction = metrics.NewTagCounter("algod_agreement_validate_exit_action_{TAG}", "Number of processValidateMessage exits per action: accept, ignore, disconnect, ctxdone, drop",
	"accept", "ignore", "disconnect", "ctxdone", "drop")
var validateMessageMicros = metrics.MakeCounter(
	metrics.MetricName{Name: "algod_agreement_validate_micros", Description: "Cumulative microseconds spent inside processValidateMessage"})
var validateMessageMicrosByType = metrics.NewTagCounter("algod_agreement_validate_micros_{TAG}", "µs spent in processValidateMessage by agreement {TAG}",
	agreementVoteMessageType, agreementProposalMessageType, agreementBundleMessageType)
var validateMessageInflight = metrics.MakeGauge(
	metrics.MetricName{Name: "algod_agreement_validate_inflight", Description: "Current number of in-flight processValidateMessage goroutines"})

// syncCh handshake counters. The signal counters increment when Relay/Disconnect/Ignore
// successfully hand a result to a parked validator goroutine. The dropped counters
// increment when the non-blocking send loses the race (default branch taken),
// which is the failure mode that leaks validator goroutines / produces ctxdone exits.
var syncChSignalByAction = metrics.NewTagCounter("algod_agreement_syncch_signal_{TAG}", "Number of successful syncCh signals by action",
	"accept", "ignore", "disconnect")
var syncChSignalDroppedByAction = metrics.NewTagCounter("algod_agreement_syncch_signal_dropped_{TAG}", "Number of syncCh signal attempts that took the default branch (no parked receiver) by action",
	"relay", "ignore", "disconnect")

// syncCh wait-time instrumentation. This is the time the validator goroutine
// spent blocked on <-syncCh, i.e. waiting for the agreement state machine to
// emit a relay/ignore/disconnect action for the message. This is essentially
// the per-message agreement processing latency. The cumulative micros are
// per-type so we can compare proposals (which include async crypto verification)
// against votes. The bucket counters give a coarse distribution so the P99 tail
// (which is what saturates pubsub's validate queue/throttle during bursts) is
// visible — long tails here directly explain bursts of gs_reject_full/throttled.
var validateSyncWaitMicros = metrics.MakeCounter(
	metrics.MetricName{Name: "algod_agreement_validate_syncwait_micros", Description: "Cumulative microseconds spent waiting on syncCh inside processValidateMessage"})
var validateSyncWaitMicrosByType = metrics.NewTagCounter("algod_agreement_validate_syncwait_micros_{TAG}", "µs spent waiting on syncCh, by agreement {TAG}",
	agreementVoteMessageType, agreementProposalMessageType, agreementBundleMessageType)

// validateSyncWaitBucketByType bins each syncCh-wait into a coarse latency
// bucket. Tag names are sortable so dashboards can stack them. Tag layout:
// "<type>_<bucket>" — e.g. "vote_lt10ms". 6 buckets × 3 types = 18 tags.
var validateSyncWaitBucketByType = metrics.NewTagCounter("algod_agreement_validate_syncwait_bucket_{TAG}", "syncCh-wait latency distribution, tag is <type>_<bucket>",
	"vote_lt1ms", "vote_lt10ms", "vote_lt100ms", "vote_lt1s", "vote_lt10s", "vote_ge10s",
	"proposal_lt1ms", "proposal_lt10ms", "proposal_lt100ms", "proposal_lt1s", "proposal_lt10s", "proposal_ge10s",
	"bundle_lt1ms", "bundle_lt10ms", "bundle_lt100ms", "bundle_lt1s", "bundle_lt10s", "bundle_ge10s",
)

// peakSyncWaitMicros holds the running peak (Hwm) syncCh-wait observed across
// process lifetime; surfaced via a gauge so a single Prometheus scrape captures
// it. Reset is intentionally not provided — peaks are sticky on purpose.
var validateSyncWaitPeakMicros = metrics.MakeGauge(
	metrics.MetricName{Name: "algod_agreement_validate_syncwait_peak_micros", Description: "Lifetime peak syncCh wait time, in microseconds"})

var validateSyncWaitPeak atomic.Uint64

func syncWaitBucketTag(msgType string, micros int64) string {
	switch {
	case micros < 1_000:
		return msgType + "_lt1ms"
	case micros < 10_000:
		return msgType + "_lt10ms"
	case micros < 100_000:
		return msgType + "_lt100ms"
	case micros < 1_000_000:
		return msgType + "_lt1s"
	case micros < 10_000_000:
		return msgType + "_lt10s"
	default:
		return msgType + "_ge10s"
	}
}

// (networkAction emission counters live in agreement/actions.go where they fire.)

// per-type in-flight counters, surfaced via the validateMessageInflight gauge.
// Atomics avoid taking a lock on every hot-path message.
var (
	validateInflightVote     atomic.Int64
	validateInflightProposal atomic.Int64
	validateInflightBundle   atomic.Int64
)

func inflightForType(msgType string) *atomic.Int64 {
	switch msgType {
	case agreementVoteMessageType:
		return &validateInflightVote
	case agreementProposalMessageType:
		return &validateInflightProposal
	case agreementBundleMessageType:
		return &validateInflightBundle
	}
	return nil
}

const (
	agreementVoteMessageType     = "vote"
	agreementProposalMessageType = "proposal"
	agreementBundleMessageType   = "bundle"
)

type messageMetadata struct {
	raw    network.IncomingMessage
	syncCh chan network.ForwardingPolicy
}

// networkImpl wraps network.GossipNode to provide a compatible interface with agreement.
type networkImpl struct {
	voteCh     chan agreement.Message
	proposalCh chan agreement.Message
	bundleCh   chan agreement.Message

	net network.GossipNode
	log logging.Logger

	trace messagetracer.MessageTracer

	ctx context.Context
}

// HybridRelayer is an interface for relaying p2p transactions to WS network
type HybridRelayer interface {
	BridgeP2PToWS(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except network.Peer) error
}

// WrapNetwork adapts a network.GossipNode into an agreement.Network.
func WrapNetwork(net network.GossipNode, log logging.Logger, cfg config.Local) agreement.Network {
	i := new(networkImpl)

	i.voteCh = make(chan agreement.Message, cfg.AgreementIncomingVotesQueueLength)
	i.proposalCh = make(chan agreement.Message, cfg.AgreementIncomingProposalsQueueLength)
	i.bundleCh = make(chan agreement.Message, cfg.AgreementIncomingBundlesQueueLength)

	i.net = net
	i.log = log

	return i
}

// SetTrace modifies the result of WrapNetwork to add network propagation tracing
func SetTrace(net agreement.Network, trace messagetracer.MessageTracer) {
	i := net.(*networkImpl)
	i.trace = trace
}

func (i *networkImpl) Start(ctx context.Context) {
	handlers := []network.TaggedMessageHandler{
		{Tag: protocol.AgreementVoteTag, MessageHandler: network.HandlerFunc(i.processVoteMessage)},
		{Tag: protocol.ProposalPayloadTag, MessageHandler: network.HandlerFunc(i.processProposalMessage)},
		{Tag: protocol.VoteBundleTag, MessageHandler: network.HandlerFunc(i.processBundleMessage)},
	}
	i.net.RegisterHandlers(handlers)

	validateHandlers := []network.TaggedMessageValidatorHandler{
		{Tag: protocol.AgreementVoteTag, MessageHandler: network.ValidateHandleFunc(i.processValidateVoteMessage)},
		{Tag: protocol.ProposalPayloadTag, MessageHandler: network.ValidateHandleFunc(i.processValidateProposalMessage)},
		{Tag: protocol.VoteBundleTag, MessageHandler: network.ValidateHandleFunc(i.processValidateBundleMessage)},
	}
	i.net.RegisterValidatorHandlers(validateHandlers)
	i.ctx = ctx
}

func messageMetadataFromHandle(h agreement.MessageHandle) *messageMetadata {
	if msg, isMsg := h.(*messageMetadata); isMsg {
		return msg
	}
	return nil
}

func (i *networkImpl) processVoteMessage(raw network.IncomingMessage) network.OutgoingMessage {
	return i.processMessage(raw, i.voteCh, agreementVoteMessageType)
}

func (i *networkImpl) processValidateVoteMessage(raw network.IncomingMessage) network.OutgoingMessage {
	return i.processValidateMessage(raw, i.voteCh, agreementVoteMessageType)
}

func (i *networkImpl) processProposalMessage(raw network.IncomingMessage) network.OutgoingMessage {
	if i.trace != nil {
		i.trace.HashTrace(messagetracer.Proposal, raw.Data)
	}
	return i.processMessage(raw, i.proposalCh, agreementProposalMessageType)
}

func (i *networkImpl) processValidateProposalMessage(raw network.IncomingMessage) network.OutgoingMessage {
	if i.trace != nil {
		i.trace.HashTrace(messagetracer.Proposal, raw.Data)
	}
	return i.processValidateMessage(raw, i.proposalCh, agreementProposalMessageType)
}

func (i *networkImpl) processBundleMessage(raw network.IncomingMessage) network.OutgoingMessage {
	return i.processMessage(raw, i.bundleCh, agreementBundleMessageType)
}

func (i *networkImpl) processValidateBundleMessage(raw network.IncomingMessage) network.OutgoingMessage {
	return i.processValidateMessage(raw, i.bundleCh, agreementBundleMessageType)
}

// i.e. process<Type>Message
func (i *networkImpl) processMessage(raw network.IncomingMessage, submit chan<- agreement.Message, msgType string) network.OutgoingMessage {
	metadata := &messageMetadata{raw: raw}

	select {
	case submit <- agreement.Message{MessageHandle: agreement.MessageHandle(metadata), Data: raw.Data}:
		// It would be slightly better to measure at de-queue
		// time, but that happens in many places in code and
		// this is much easier.
		messagesHandledTotal.Inc(nil)
		messagesHandledByType.Add(msgType, 1)
	default:
		messagesDroppedTotal.Inc(nil)
		messagesDroppedByType.Add(msgType, 1)
	}

	// Immediately ignore everything here, sometimes Relay/Broadcast/Disconnect later based on API handles saved from IncomingMessage
	return network.OutgoingMessage{Action: network.Ignore}
}

// i.e. process<Type>Message
func (i *networkImpl) processValidateMessage(raw network.IncomingMessage, submit chan<- agreement.Message, msgType string) network.OutgoingMessage {
	start := time.Now()
	validateMessageEntryByType.Add(msgType, 1)
	inflight := inflightForType(msgType)
	if inflight != nil {
		validateMessageInflight.Set(uint64(inflight.Add(1)))
	}

	metadata := &messageMetadata{
		raw:    raw,
		syncCh: make(chan network.ForwardingPolicy),
	}

	var action network.ForwardingPolicy
	// exitReason classifies how the validator returned, so a growing share of
	// "ctxdone" exits cleanly indicates validator-leak / hang behavior.
	exitReason := "drop"
	// syncWaitMicros records the time spent blocked on <-syncCh (or ctx.Done()),
	// i.e. the per-message agreement processing latency. It's the chunk we expect
	// to dominate total processValidateMessage time, and is what saturates
	// pubsub's validate queue/throttle during step-deadline bursts.
	var syncWaitMicros int64
	select {
	case submit <- agreement.Message{MessageHandle: agreement.MessageHandle(metadata), Data: raw.Data}:
		syncWaitStart := time.Now()
		select {
		case action = <-metadata.syncCh:
			switch action {
			case network.Accept:
				exitReason = "accept"
			case network.Disconnect:
				exitReason = "disconnect"
			default:
				exitReason = "ignore"
			}
		case <-i.ctx.Done():
			action = network.Ignore
			exitReason = "ctxdone"
		}
		syncWaitMicros = time.Since(syncWaitStart).Microseconds()
		messagesHandledTotal.Inc(nil)
		messagesHandledByType.Add(msgType, 1)
	default:
		messagesDroppedTotal.Inc(nil)
		messagesDroppedByType.Add(msgType, 1)
		action = network.Ignore
		exitReason = "drop"
	}

	if hybridNet, ok := i.net.(HybridRelayer); ok && action == network.Accept {
		_ = hybridNet.BridgeP2PToWS(i.ctx, raw.Tag, raw.Data, false, metadata.raw.Sender)
	}

	validateMessageMicros.AddMicrosecondsSince(start, nil)
	validateMessageMicrosByType.Add(msgType, uint64(time.Since(start).Microseconds()))
	validateMessageExitByType.Add(msgType, 1)
	validateMessageExitByAction.Add(exitReason, 1)
	if exitReason != "drop" {
		// only record syncCh-wait for messages that actually entered the wait;
		// the "drop" case never started the inner select.
		validateSyncWaitMicros.AddUint64(uint64(syncWaitMicros), nil)
		validateSyncWaitMicrosByType.Add(msgType, uint64(syncWaitMicros))
		validateSyncWaitBucketByType.Add(syncWaitBucketTag(msgType, syncWaitMicros), 1)
		// Lock-free running peak: CAS only when our sample beats the current peak.
		for {
			prev := validateSyncWaitPeak.Load()
			if uint64(syncWaitMicros) <= prev {
				break
			}
			if validateSyncWaitPeak.CompareAndSwap(prev, uint64(syncWaitMicros)) {
				validateSyncWaitPeakMicros.Set(uint64(syncWaitMicros))
				break
			}
		}
	}
	if inflight != nil {
		validateMessageInflight.Set(uint64(inflight.Add(-1)))
	}

	// The action is returned synchronously via syncCh. Subsequent Relay, Broadcast, or Disconnect calls may occur asynchronously using the saved message handle from IncomingMessage.
	return network.OutgoingMessage{Action: action}
}

func (i *networkImpl) Messages(t protocol.Tag) <-chan agreement.Message {
	switch t {
	case protocol.AgreementVoteTag:
		return i.voteCh
	case protocol.ProposalPayloadTag:
		return i.proposalCh
	case protocol.VoteBundleTag:
		return i.bundleCh
	default:
		i.log.Panicf("bad tag! %v", t)
		return nil
	}
}

func (i *networkImpl) Broadcast(t protocol.Tag, data []byte) (err error) {
	err = i.net.Broadcast(context.Background(), t, data, false, nil)
	if err != nil {
		i.log.Infof("agreement: could not broadcast message with tag %v: %v", t, err)
	}
	return
}

func (i *networkImpl) Relay(h agreement.MessageHandle, t protocol.Tag, data []byte) (err error) {
	metadata := messageMetadataFromHandle(h)
	if metadata == nil { // synthetic loopback
		err = i.net.Broadcast(context.Background(), t, data, false, nil)
		if err != nil {
			i.log.Infof("agreement: could not (pseudo)relay message with tag %v: %v", t, err)
		}
	} else {
		if metadata.syncCh != nil {
			// Synchronous validation path
			select {
			case metadata.syncCh <- network.Accept:
				syncChSignalByAction.Add("accept", 1)
				return
			default:
				// validator already returned; do real relay
				syncChSignalDroppedByAction.Add("relay", 1)
			}
		}
		err = i.net.Relay(context.Background(), t, data, false, metadata.raw.Sender)
		if err != nil {
			i.log.Infof("agreement: could not relay message from %v with tag %v: %v", metadata.raw.Sender, t, err)
		}
	}
	return
}

func (i *networkImpl) Disconnect(h agreement.MessageHandle) {
	metadata := messageMetadataFromHandle(h)

	if metadata == nil { // synthetic loopback
		i.log.Warnf("agreement: Disconnect without message handle")
		return
	}

	if metadata.syncCh != nil {
		// Synchronous validation path
		select {
		case metadata.syncCh <- network.Disconnect:
			syncChSignalByAction.Add("disconnect", 1)
			return
		default:
			// validator already returned; do real disconnect
			syncChSignalDroppedByAction.Add("disconnect", 1)
		}
	}
	i.net.Disconnect(metadata.raw.Sender)
}

func (i *networkImpl) Ignore(h agreement.MessageHandle) {
	metadata := messageMetadataFromHandle(h)

	if metadata == nil { // synthetic loopback
		i.log.Warnf("agreement: Ignore without message handle")
		return
	}

	if metadata.syncCh != nil {
		// Synchronous validation path
		select {
		case metadata.syncCh <- network.Ignore:
			syncChSignalByAction.Add("ignore", 1)
			return
		default:
			syncChSignalDroppedByAction.Add("ignore", 1)
		}
	}
}
