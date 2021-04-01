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

package agreement

import (
	"context"
	"fmt"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"io"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/logspec"
	"github.com/algorand/go-algorand/protocol"
)

const (
	eventQueueDemux                  = "demux"
	eventQueueCryptoVerifierVote     = "cryptoVerifierVote"
	eventQueueCryptoVerifierProposal = "cryptoVerifierProposal"
	eventQueueCryptoVerifierBundle   = "cryptoVerifierBundle"
	eventQueuePseudonode             = "pseudonode"
)

var eventQueueTokenizing = map[protocol.Tag]string{
	protocol.AgreementVoteTag:   "TokenizingVote",
	protocol.ProposalPayloadTag: "TokenizingProposal",
	protocol.VoteBundleTag:      "TokenizingBundle",
}

var eventQueueTokenized = map[protocol.Tag]string{
	protocol.AgreementVoteTag:   "TokenizedVote",
	protocol.ProposalPayloadTag: "TokenizedProposal",
	protocol.VoteBundleTag:      "TokenizedBundle",
}

// demux is a demultiplexer which supplies the state machine the next relevant external input.
//
// demux is not thread-safe and assumes all calls are serialized.
type demux struct {
	crypto cryptoVerifier
	ledger LedgerReader

	rawVotes     <-chan message
	rawProposals <-chan message
	rawBundles   <-chan message

	queue             []<-chan externalEvent
	processingMonitor EventsProcessingMonitor
	monitor           *coserviceMonitor
	cancelTokenizers  context.CancelFunc

	log logging.Logger
}

// demuxParams contains the parameters required to initliaze a new demux object
type demuxParams struct {
	net               Network
	ledger            LedgerReader
	validator         BlockValidator
	voteVerifier      *AsyncVoteVerifier
	processingMonitor EventsProcessingMonitor
	log               logging.Logger
	monitor           *coserviceMonitor
}

// makeDemux initializes the goroutines needed to process external events, setting up the appropriate channels.
//
// It must be called before other methods are called.
func makeDemux(params demuxParams) (d *demux) {
	d = new(demux)
	d.crypto = makeCryptoVerifier(params.ledger, params.validator, params.voteVerifier, params.log)
	d.log = params.log
	d.ledger = params.ledger
	d.monitor = params.monitor
	d.queue = make([]<-chan externalEvent, 0)
	d.processingMonitor = params.processingMonitor

	tokenizerCtx, cancelTokenizers := context.WithCancel(context.Background())
	d.rawVotes = d.tokenizeMessages(tokenizerCtx, params.net, protocol.AgreementVoteTag, decodeVote)
	d.rawProposals = d.tokenizeMessages(tokenizerCtx, params.net, protocol.ProposalPayloadTag, decodeProposal)
	d.rawBundles = d.tokenizeMessages(tokenizerCtx, params.net, protocol.VoteBundleTag, decodeBundle)
	d.cancelTokenizers = cancelTokenizers

	return d
}

func (d *demux) UpdateEventsQueue(queueName string, queueLength int) {
	if d.processingMonitor == nil {
		return
	}
	d.processingMonitor.UpdateEventsQueue(queueName, queueLength)
}

func ReconstructProposal(s *Service, b *bookkeeping.Block, h MessageHandle) error {
	if b.Payset == nil {
		b.Payset = make(transactions.Payset, len(b.PaysetDigest))
	}
	if s.BlockFactory != nil {
		if err := s.BlockFactory.ReconstructBlock(b); err != nil {
			return err
		}
	} else {
		logging.Base().Warnf("failed to reconstruct block: BlockFactory was nil")
	}
	logging.Base().Infof("len %v", len(b.PaysetDigest))
	stxnsData, allPresent := s.Network.LoadMessage(h, b.PaysetDigest)
	if !allPresent {
		logging.Base().Warnf("could not recover txns")
	} else {
		logging.Base().Warnf("could recover txns")
	}

	var dec protocol.Decoder

	count := 0
	for i, stxnData := range stxnsData {
		if b.Payset[i].SignedTxn.MsgIsZero() && stxnData != nil {
			dec = protocol.NewDecoderBytes(stxnData)
			err := dec.Decode(&b.Payset[i].SignedTxn)
			if err == io.EOF {
				break
			}
			if err != nil {
				logging.Base().Warnf("Received a non-decodable txn: %v", err)
				//net.Disconnect(raw.MessageHandle)
				return err
			}
		}
		if b.Payset[i].SignedTxn.MsgIsZero() {
			count += 1
		} else {
			var err error
			b.Payset[i], err = b.EncodeSignedTxn(b.Payset[i].SignedTxn, transactions.ApplyData{})
			if err != nil {
				return err
			}
		}
	}
	if count > 0 {
		return fmt.Errorf("%v txns missing from %v", count, len(b.PaysetDigest))
	}

	logging.Base().Infof("done %v", len(b.Payset))
	return nil
}

// tokenizeMessages tokenizes a raw message stream
func (d *demux) tokenizeMessages(ctx context.Context, net Network, tag protocol.Tag, tokenize streamTokenizer) <-chan message {
	networkMessages := net.Messages(tag)
	decoded := make(chan message)
	go func() {
		defer func() {
			close(decoded)
		}()
		for {
			select {
			case raw, ok := <-networkMessages:
				if !ok {
					return
				}
				d.UpdateEventsQueue(eventQueueTokenizing[tag], 1)

				o, err := tokenize(raw.Data)
				if err != nil {
					logging.Base().Warnf("disconnecting from peer: error decoding message tagged %v: %v", tag, err)
					net.Disconnect(raw.MessageHandle)
					d.UpdateEventsQueue(eventQueueTokenizing[tag], 0)
					continue
				}

				var msg message
				switch tag {
				case protocol.AgreementVoteTag:
					msg = message{MessageHandle: raw.MessageHandle, Tag: tag, UnauthenticatedVote: o.(unauthenticatedVote)}
				case protocol.VoteBundleTag:
					msg = message{MessageHandle: raw.MessageHandle, Tag: tag, UnauthenticatedBundle: o.(unauthenticatedBundle)}
				case protocol.ProposalPayloadTag:
					msg = message{MessageHandle: raw.MessageHandle, Tag: tag, CompoundMessage: o.(compoundMessage)}
				default:
					err := fmt.Errorf("bad message tag: %v", tag)
					d.UpdateEventsQueue(fmt.Sprintf("Tokenizing-%s", tag), 0)
					panic(err)
				}
				d.UpdateEventsQueue(eventQueueTokenized[tag], 1)
				d.UpdateEventsQueue(eventQueueTokenizing[tag], 0)

				select {
				case decoded <- msg:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return decoded
}

// verifyVote enqueues a vote message to be verified.
func (d *demux) verifyVote(ctx context.Context, m message, taskIndex int, r round, p period) {
	d.UpdateEventsQueue(eventQueueCryptoVerifierVote, 1)
	d.monitor.inc(cryptoVerifierCoserviceType)
	d.crypto.VerifyVote(ctx, cryptoVoteRequest{message: m, TaskIndex: taskIndex, Round: r, Period: p})
}

// verifyPayload enqueues a proposal payload message to be verified.
func (d *demux) verifyPayload(ctx context.Context, m message, r round, p period, pinned bool) {
	d.UpdateEventsQueue(eventQueueCryptoVerifierProposal, 1)
	d.monitor.inc(cryptoVerifierCoserviceType)
	d.crypto.VerifyProposal(ctx, &cryptoProposalRequest{message: m, Round: r, Period: p, Pinned: pinned})
}

// verifyBundle enqueues a bundle message to be verified.
func (d *demux) verifyBundle(ctx context.Context, m message, r round, p period, s step) {
	d.UpdateEventsQueue(eventQueueCryptoVerifierBundle, 1)
	d.monitor.inc(cryptoVerifierCoserviceType)
	d.crypto.VerifyBundle(ctx, cryptoBundleRequest{message: m, Round: r, Period: p, Certify: s == cert})
}

// next blocks until it observes an external input event of interest for the state machine.
//
// If ok is false, there are no more events so the agreement service should quit.
func (d *demux) next(s *Service, deadline time.Duration, fastDeadline time.Duration, currentRound round) (e externalEvent, ok bool) {
	defer func() {
		if !ok {
			return
		}
		proto, err := d.ledger.ConsensusVersion(ParamsRound(e.ConsensusRound()))
		e = e.AttachConsensusVersion(ConsensusVersionView{Err: makeSerErr(err), Version: proto})
	}()

	var pseudonodeEvents <-chan externalEvent
	for len(d.queue) > 0 && pseudonodeEvents == nil {
		d.UpdateEventsQueue(eventQueuePseudonode, 1)
		select {
		case e, ok = <-d.queue[0]:
			if ok {
				if e.t() != checkpointReached {
					d.monitor.dec(pseudonodeCoserviceType)
				}
				return
			}
			d.queue = d.queue[1:]
			d.UpdateEventsQueue(eventQueuePseudonode, 0)
		case <-s.quit:
			return emptyEvent{}, false
		default:
			// the queue[0] has a channel which is open, but empty.
			pseudonodeEvents = d.queue[0]
		}

	}

	nextRound := currentRound
	ok = true

	rawVotes := d.rawVotes
	rawProposals := d.rawProposals
	rawBundles := d.rawBundles

	// Stop reading off the network if our goroutine pool has no space.
	//
	// This prevents deadlock: the only producer to the pool is its consumer.
	if d.crypto.ChannelFull(protocol.AgreementVoteTag) {
		rawVotes = nil
		rawProposals = nil // a vote may be attached to proposal payloads
	}
	if d.crypto.ChannelFull(protocol.ProposalPayloadTag) {
		rawProposals = nil
	}
	if d.crypto.ChannelFull(protocol.VoteBundleTag) {
		rawBundles = nil
	}

	ledgerNextRoundCh := s.Ledger.Wait(nextRound)
	deadlineCh := s.Clock.TimeoutAt(deadline)
	var fastDeadlineCh <-chan time.Time

	fastPartitionRecoveryEnabled := false
	if proto, err := d.ledger.ConsensusVersion(ParamsRound(currentRound)); err != nil {
		logging.Base().Warnf("demux: could not get consensus parameters for round %d: %v", ParamsRound(currentRound), err)
		// this might happen during catchup, since the Ledger.Wait fires as soon as a new block is recieved by the ledger, which could be
		// far before it's being committed. In these cases, it should be safe to default to the current consensus version. On subsequent
		// iterations, it will get "corrected" since the ledger would finish flushing the blocks to disk.
		fastPartitionRecoveryEnabled = config.Consensus[protocol.ConsensusCurrentVersion].FastPartitionRecovery
	} else {
		fastPartitionRecoveryEnabled = config.Consensus[proto].FastPartitionRecovery
	}

	if fastPartitionRecoveryEnabled {
		fastDeadlineCh = s.Clock.TimeoutAt(fastDeadline)
	}

	d.UpdateEventsQueue(eventQueueDemux, 0)
	d.monitor.dec(demuxCoserviceType)

	select {
	case e, ok = <-pseudonodeEvents:
		d.UpdateEventsQueue(eventQueueDemux, 1)
		d.monitor.inc(demuxCoserviceType)
		if ok {
			if e.t() != checkpointReached {
				d.monitor.dec(pseudonodeCoserviceType)
			}
			return
		}
		// the pseudonode channel got closed. remove it from the queue and try again.
		d.queue = d.queue[1:]
		d.UpdateEventsQueue(eventQueuePseudonode, 0)
		return d.next(s, deadline, fastDeadline, currentRound)

	// control
	case <-s.quit:
		e = emptyEvent{}
		ok = false

	// external
	case <-ledgerNextRoundCh:
		// The round nextRound have reached externally ( most likely by the catchup service )
		// since we don't know how long we've been waiting in this select statement and we don't really know
		// if the current next round has been increased by 1 or more, we need to sample it again.
		previousRound := nextRound
		nextRound = s.Ledger.NextRound()

		logEvent := logspec.AgreementEvent{
			Type:  logspec.RoundInterrupted,
			Round: uint64(previousRound),
		}

		s.log.with(logEvent).Infof("agreement: round %d ended early due to concurrent write; next round is %d", previousRound, nextRound)
		e = roundInterruptionEvent{Round: nextRound}
		d.UpdateEventsQueue(eventQueueDemux, 1)
		d.monitor.inc(demuxCoserviceType)
	case <-deadlineCh:
		e = timeoutEvent{T: timeout, RandomEntropy: s.RandomSource.Uint64(), Round: nextRound}
		d.UpdateEventsQueue(eventQueueDemux, 1)
		d.monitor.inc(demuxCoserviceType)
		d.monitor.dec(clockCoserviceType)
	case <-fastDeadlineCh:
		e = timeoutEvent{T: fastTimeout, RandomEntropy: s.RandomSource.Uint64(), Round: nextRound}
		d.UpdateEventsQueue(eventQueueDemux, 1)
		d.monitor.inc(demuxCoserviceType)
		d.monitor.dec(clockCoserviceType)

	// raw
	case m, open := <-rawVotes:
		if !open {
			return emptyEvent{}, false
		}
		e = messageEvent{T: votePresent, Input: m}
		d.UpdateEventsQueue(eventQueueDemux, 1)
		d.UpdateEventsQueue(eventQueueTokenized[protocol.AgreementVoteTag], 0)
		d.monitor.inc(demuxCoserviceType)
		d.monitor.dec(tokenizerCoserviceType)
	case m, open := <-rawProposals:
		if !open {
			return emptyEvent{}, false
		}
		e = setupCompoundMessage(d.ledger, m, s)
		d.UpdateEventsQueue(eventQueueDemux, 1)
		d.UpdateEventsQueue(eventQueueTokenized[protocol.ProposalPayloadTag], 0)
		d.monitor.inc(demuxCoserviceType)
		d.monitor.dec(tokenizerCoserviceType)
	case m, open := <-rawBundles:
		if !open {
			return emptyEvent{}, false
		}
		e = messageEvent{T: bundlePresent, Input: m}
		d.UpdateEventsQueue(eventQueueDemux, 1)
		d.UpdateEventsQueue(eventQueueTokenized[protocol.VoteBundleTag], 0)
		d.monitor.inc(demuxCoserviceType)
		d.monitor.dec(tokenizerCoserviceType)

	// authenticated
	case r := <-d.crypto.VerifiedVotes():
		e = messageEvent{T: voteVerified, Input: r.message, TaskIndex: r.index, Err: makeSerErr(r.err), Cancelled: r.cancelled}
		d.UpdateEventsQueue(eventQueueDemux, 1)
		d.UpdateEventsQueue(eventQueueCryptoVerifierVote, 0)
		d.monitor.inc(demuxCoserviceType)
		d.monitor.dec(cryptoVerifierCoserviceType)
	case r := <-d.crypto.Verified(protocol.ProposalPayloadTag):
		e = messageEvent{T: payloadVerified, Input: r.message, Err: r.Err, Cancelled: r.Cancelled}
		d.UpdateEventsQueue(eventQueueDemux, 1)
		d.UpdateEventsQueue(eventQueueCryptoVerifierProposal, 0)
		d.monitor.inc(demuxCoserviceType)
		d.monitor.dec(cryptoVerifierCoserviceType)
	case r := <-d.crypto.Verified(protocol.VoteBundleTag):
		e = messageEvent{T: bundleVerified, Input: r.message, Err: r.Err, Cancelled: r.Cancelled}
		d.UpdateEventsQueue(eventQueueDemux, 1)
		d.UpdateEventsQueue(eventQueueCryptoVerifierBundle, 0)
		d.monitor.inc(demuxCoserviceType)
		d.monitor.dec(cryptoVerifierCoserviceType)
	}

	return
}

// setupCompoundMessage processes compound messages: distinct messages which are delivered together
func setupCompoundMessage(l LedgerReader, m message, s *Service) (res externalEvent) {
	compound := m.CompoundMessage
	if err := ReconstructProposal(s, &compound.Proposal.Block, m.MessageHandle); err != nil {
		logging.Base().Warnf("Failed to reconstruct proposal: %v", err)
		return emptyEvent{}
	}
	if compound.Vote == (unauthenticatedVote{}) {
		m.Tag = protocol.ProposalPayloadTag
		m.UnauthenticatedProposal = compound.Proposal
		res = messageEvent{T: payloadPresent, Input: m}
		return
	}

	tailmsg := message{MessageHandle: m.MessageHandle, Tag: protocol.ProposalPayloadTag, UnauthenticatedProposal: compound.Proposal}
	synthetic := messageEvent{T: payloadPresent, Input: tailmsg}
	proto, err := l.ConsensusVersion(ParamsRound(synthetic.ConsensusRound()))
	synthetic = synthetic.AttachConsensusVersion(ConsensusVersionView{Err: makeSerErr(err), Version: proto}).(messageEvent)

	m.Tag = protocol.AgreementVoteTag
	m.UnauthenticatedVote = compound.Vote
	res = messageEvent{T: votePresent, Input: m, Tail: &synthetic}

	return
}

// prioritize sets a channel of events to deliver events to the state machine ahead of other input.
//
// If the source has a limited amount of input, it must close the channel.
// The demux will not return other events until the channel is closed.
//
// If prioritize has been called a second time before the first channel was closed,
// it will finish processing the first channel before starting the second.
// In other words, the queue of channels is FIFO.
func (d *demux) prioritize(c <-chan externalEvent) {
	d.queue = append(d.queue, c)
	d.UpdateEventsQueue(eventQueuePseudonode, 1)
}

// quit indicates to this demux that it should quit.
func (d *demux) quit() {
	d.crypto.Quit()
	d.cancelTokenizers()
}
