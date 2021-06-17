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

package catchup

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

const catchupPeersForSync = 10
const blockQueryPeerLimit = 10

// this should be at least the number of relays
const catchupRetryLimit = 500

// PendingUnmatchedCertificate is a single certificate that is being waited upon to have its corresponding block fetched.
type PendingUnmatchedCertificate struct {
	Cert         agreement.Certificate
	VoteVerifier *agreement.AsyncVoteVerifier
}

// Ledger represents the interface of a block database which the
// catchup server should interact with.
type Ledger interface {
	agreement.LedgerReader
	AddBlock(bookkeeping.Block, agreement.Certificate) error
	EnsureBlock(block *bookkeeping.Block, c agreement.Certificate)
	LastRound() basics.Round
	Block(basics.Round) (bookkeeping.Block, error)
	IsWritingCatchpointFile() bool
	Validate(ctx context.Context, blk bookkeeping.Block, executionPool execpool.BacklogPool) (*ledger.ValidatedBlock, error)
	AddValidatedBlock(vb ledger.ValidatedBlock, cert agreement.Certificate) error
}

// Service represents the catchup service. Once started and until it is stopped, it ensures that the ledger is up to date with network.
type Service struct {
	syncStartNS         int64 // at top of struct to keep 64 bit aligned for atomic.* ops
	cfg                 config.Local
	ledger              Ledger
	ctx                 context.Context
	cancel              func()
	done                chan struct{}
	log                 logging.Logger
	net                 network.GossipNode
	auth                BlockAuthenticator
	parallelBlocks      uint64
	deadlineTimeout     time.Duration
	blockValidationPool execpool.BacklogPool

	// suspendForCatchpointWriting defines whether we've ran into a state where the ledger is currently busy writing the
	// catchpoint file. If so, we want to suspend the catchup process until the catchpoint file writing is complete,
	// and resume from there without stopping the catchup timer.
	suspendForCatchpointWriting bool

	// The channel gets closed when the initial sync is complete. This allows for other services to avoid
	// the overhead of starting prematurely (before this node is caught-up and can validate messages for example).
	InitialSyncDone              chan struct{}
	initialSyncNotified          uint32
	protocolErrorLogged          bool
	lastSupportedRound           basics.Round
	unmatchedPendingCertificates <-chan PendingUnmatchedCertificate
}

// A BlockAuthenticator authenticates blocks given a certificate.
//
// Note that Authenticate does not check if the block contents match
// their header as it only checks the block header.  If the contents
// have not been checked yet, callers should also call
// block.ContentsMatchHeader and reject blocks that do not pass this
// check.
type BlockAuthenticator interface {
	Authenticate(*bookkeeping.Block, *agreement.Certificate) error
	Quit()
}

// MakeService creates a catchup service instance from its constituent components
func MakeService(log logging.Logger, config config.Local, net network.GossipNode, ledger Ledger, auth BlockAuthenticator, unmatchedPendingCertificates <-chan PendingUnmatchedCertificate, blockValidationPool execpool.BacklogPool) (s *Service) {
	s = &Service{}

	s.cfg = config
	s.ledger = ledger
	s.net = net
	s.auth = auth
	s.unmatchedPendingCertificates = unmatchedPendingCertificates
	s.log = log.With("Context", "sync")
	s.parallelBlocks = config.CatchupParallelBlocks
	s.deadlineTimeout = agreement.DeadlineTimeout()
	s.blockValidationPool = blockValidationPool

	return s
}

// Start the catchup service
func (s *Service) Start() {
	s.done = make(chan struct{})
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.InitialSyncDone = make(chan struct{})
	go s.periodicSync()
}

// Stop informs the catchup service that it should stop, and waits for it to stop (when periodicSync() exits)
func (s *Service) Stop() {
	s.cancel()
	<-s.done
	if atomic.CompareAndSwapUint32(&s.initialSyncNotified, 0, 1) {
		close(s.InitialSyncDone)
	}
}

// IsSynchronizing returns true if we're currently executing a sync() call - either initial catchup
// or attempting to catchup after too-long waiting for next block.
// Also returns a 2nd bool indicating if this is our initial sync
func (s *Service) IsSynchronizing() (synchronizing bool, initialSync bool) {
	synchronizing = atomic.LoadInt64(&s.syncStartNS) != 0
	initialSync = atomic.LoadUint32(&s.initialSyncNotified) == 0
	return
}

// SynchronizingTime returns the time we've been performing a catchup operation (0 if not currently catching up)
func (s *Service) SynchronizingTime() time.Duration {
	startNS := atomic.LoadInt64(&s.syncStartNS)
	if startNS == 0 {
		return time.Duration(0)
	}
	timeInNS := time.Now().UnixNano()
	return time.Duration(timeInNS - startNS)
}

// function scope to make a bunch of defer statements better
func (s *Service) innerFetch(r basics.Round, peer network.Peer) (blk *bookkeeping.Block, cert *agreement.Certificate, ddur time.Duration, err error) {
	ctx, cf := context.WithCancel(s.ctx)
	fetcher := makeUniversalBlockFetcher(s.log, s.net, s.cfg)
	defer cf()
	stopWaitingForLedgerRound := make(chan struct{})
	defer close(stopWaitingForLedgerRound)
	go func() {
		select {
		case <-stopWaitingForLedgerRound:
		case <-s.ledger.Wait(r):
			cf()
		}
	}()
	return fetcher.fetchBlock(ctx, r, peer)
}

// fetchAndWrite fetches a block, checks the cert, and writes it to the ledger. Cert checking and ledger writing both wait for the ledger to advance if necessary.
// Returns false if we couldn't fetch or write (i.e., if we failed even after a given number of retries or if we were told to abort.)
func (s *Service) fetchAndWrite(r basics.Round, prevFetchCompleteChan chan bool, lookbackComplete chan bool, peerSelector *peerSelector) bool {
	i := 0
	hasLookback := false
	for true {
		i++
		select {
		case <-s.ctx.Done():
			s.log.Debugf("fetchAndWrite(%v): Aborted", r)
			return false
		default:
		}

		// Stop retrying after a while.
		if i > catchupRetryLimit {
			loggedMessage := fmt.Sprintf("fetchAndWrite(%d): block retrieval exceeded retry limit", r)
			if _, initialSync := s.IsSynchronizing(); initialSync {
				// on the initial sync, it's completly expected that we won't be able to get all the "next" blocks.
				// Therefore info should suffice.
				s.log.Info(loggedMessage)
			} else {
				// On any subsequent sync, we migth be looking for multiple rounds into the future, so it's completly
				// reasonable that we would fail retrieving the future block.
				// Generate a warning here only if we're failing to retrieve X+1 or below.
				// All other block retrievals should not generate a warning.
				if r > s.ledger.NextRound() {
					s.log.Info(loggedMessage)
				} else {
					s.log.Warn(loggedMessage)
				}
			}
			return false
		}

		peer, getPeerErr := peerSelector.GetNextPeer()
		if getPeerErr != nil {
			s.log.Debugf("fetchAndWrite: was unable to obtain a peer to retrieve the block from")
			break
		}

		// Try to fetch, timing out after retryInterval
		block, cert, blockDownloadDuration, err := s.innerFetch(r, peer)

		if err != nil {
			s.log.Debugf("fetchAndWrite(%v): Could not fetch: %v (attempt %d)", r, err, i)
			peerSelector.RankPeer(peer, peerRankDownloadFailed)
			// we've just failed to retrieve a block; wait until the previous block is fetched before trying again
			// to avoid the usecase where the first block doesn't exists and we're making many requests down the chain
			// for no reason.
			if !hasLookback {
				select {
				case <-s.ctx.Done():
					s.log.Infof("fetchAndWrite(%d): Aborted while waiting for lookback block to ledger after failing once : %v", r, err)
					return false
				case hasLookback = <-lookbackComplete:
					if !hasLookback {
						s.log.Infof("fetchAndWrite(%d): lookback block doesn't exist, won't try to retrieve block again : %v", r, err)
						return false
					}
				}
			}
			continue // retry the fetch
		} else if block == nil || cert == nil {
			// someone already wrote the block to the ledger, we should stop syncing
			return false
		}
		s.log.Debugf("fetchAndWrite(%v): Got block and cert contents: %v %v", r, block, cert)

		// Check that the block's contents match the block header (necessary with an untrusted block because b.Hash() only hashes the header)
		if s.cfg.CatchupVerifyPaysetHash() {
			if !block.ContentsMatchHeader() {
				peerSelector.RankPeer(peer, peerRankInvalidDownload)
				// Check if this mismatch is due to an unsupported protocol version
				if _, ok := config.Consensus[block.BlockHeader.CurrentProtocol]; !ok {
					s.log.Errorf("fetchAndWrite(%v): unsupported protocol version detected: '%v'", r, block.BlockHeader.CurrentProtocol)
					return false
				}

				s.log.Warnf("fetchAndWrite(%v): block contents do not match header (attempt %d)", r, i)
				continue // retry the fetch
			}
		}

		// make sure that we have the lookBack block that's required for authenticating this block
		if !hasLookback {
			select {
			case <-s.ctx.Done():
				s.log.Debugf("fetchAndWrite(%v): Aborted while waiting for lookback block to ledger", r)
				return false
			case hasLookback = <-lookbackComplete:
				if !hasLookback {
					s.log.Warnf("fetchAndWrite(%v): lookback block doesn't exist, cannot authenticate new block", r)
					return false
				}
			}
		}
		if s.cfg.CatchupVerifyCertificate() {
			err = s.auth.Authenticate(block, cert)
			if err != nil {
				s.log.Warnf("fetchAndWrite(%v): cert did not authenticate block (attempt %d): %v", r, i, err)
				peerSelector.RankPeer(peer, peerRankInvalidDownload)
				continue // retry the fetch
			}
		}

		peerRank := peerSelector.PeerDownloadDurationToRank(peer, blockDownloadDuration)
		r1, r2 := peerSelector.RankPeer(peer, peerRank)
		s.log.Debugf("fetchAndWrite(%d): ranked peer with %d from %d to %d", r, peerRank, r1, r2)

		// Write to ledger, noting that ledger writes must be in order
		select {
		case <-s.ctx.Done():
			s.log.Debugf("fetchAndWrite(%v): Aborted while waiting to write to ledger", r)
			return false
		case prevFetchSuccess := <-prevFetchCompleteChan:
			if prevFetchSuccess {
				// make sure the ledger wrote enough of the account data to disk, since we don't want the ledger to hold a large amount of data in memory.
				proto, err := s.ledger.ConsensusParams(r.SubSaturate(1))
				if err != nil {
					s.log.Errorf("fetchAndWrite(%d): Unable to determine consensus params for round %d: %v", r, r-1, err)
					return false
				}
				ledgerBacklogRound := r.SubSaturate(basics.Round(proto.MaxBalLookback))
				select {
				case <-s.ledger.Wait(ledgerBacklogRound):
					// i.e. round r-320 is no longer in the blockqueue, so it's account data is either being currently written, or it was already written.
				case <-s.ctx.Done():
					s.log.Debugf("fetchAndWrite(%d): Aborted while waiting for ledger to complete writing up to round %d", r, ledgerBacklogRound)
					return false
				}

				if s.cfg.CatchupVerifyTransactionSignatures() || s.cfg.CatchupVerifyApplyData() {
					vb, err := s.ledger.Validate(s.ctx, *block, s.blockValidationPool)
					if err != nil {
						if s.ctx.Err() != nil {
							// if the context expired, just exit.
							return false
						}
						s.log.Warnf("fetchAndWrite(%d): failed to validate block : %v", r, err)
						return false
					}
					err = s.ledger.AddValidatedBlock(*vb, *cert)
				} else {
					err = s.ledger.AddBlock(*block, *cert)
				}

				if err != nil {
					switch err.(type) {
					case ledgercore.BlockInLedgerError:
						s.log.Infof("fetchAndWrite(%d): block already in ledger", r)
						return true
					case protocol.Error:
						if !s.protocolErrorLogged {
							logging.Base().Errorf("fetchAndWrite(%v): unrecoverable protocol error detected: %v", r, err)
							s.protocolErrorLogged = true
						}
					default:
						s.log.Errorf("fetchAndWrite(%v): ledger write failed: %v", r, err)
					}

					return false
				}
				s.log.Debugf("fetchAndWrite(%v): Wrote block to ledger", r)
				return true
			}
			s.log.Warnf("fetchAndWrite(%v): previous block doesn't exist (perhaps fetching block %v failed)", r, r-1)
			return false
		}
	}
	return false
}

type task func() basics.Round

func (s *Service) pipelineCallback(r basics.Round, thisFetchComplete chan bool, prevFetchCompleteChan chan bool, lookbackChan chan bool, peerSelector *peerSelector) func() basics.Round {
	return func() basics.Round {
		fetchResult := s.fetchAndWrite(r, prevFetchCompleteChan, lookbackChan, peerSelector)

		// the fetch result will be read at most twice (once as the lookback block and once as the prev block, so we write the result twice)
		thisFetchComplete <- fetchResult
		thisFetchComplete <- fetchResult

		if !fetchResult {
			s.log.Infof("failed to fetch block %v", r)
			return 0
		}
		return r
	}
}

// TODO the following code does not handle the following case: seedLookback upgrades during fetch
func (s *Service) pipelinedFetch(seedLookback uint64) {
	parallelRequests := s.parallelBlocks
	if parallelRequests < seedLookback {
		parallelRequests = seedLookback
	}

	completed := make(chan basics.Round, parallelRequests)
	taskCh := make(chan task, parallelRequests)
	var wg sync.WaitGroup

	defer func() {
		close(taskCh)
		wg.Wait()
		close(completed)
	}()

	peerSelector := s.createPeerSelector(true)

	if _, err := peerSelector.GetNextPeer(); err == errPeerSelectorNoPeerPoolsAvailable {
		s.log.Debugf("pipelinedFetch: was unable to obtain a peer to retrieve the block from")
		return
	}

	// Invariant: len(taskCh) + (# pending writes to completed) <= N
	wg.Add(int(parallelRequests))
	for i := uint64(0); i < parallelRequests; i++ {
		go func() {
			defer wg.Done()
			for t := range taskCh {
				completed <- t() // This write to completed comes after a read from taskCh, so the invariant is preserved.
			}
		}()
	}

	recentReqs := make([]chan bool, 0)
	for i := 0; i < int(seedLookback); i++ {
		// the fetch result will be read at most twice (once as the lookback block and once as the prev block, so we write the result twice)
		reqComplete := make(chan bool, 2)
		reqComplete <- true
		reqComplete <- true
		recentReqs = append(recentReqs, reqComplete)
	}

	from := s.ledger.NextRound()
	nextRound := from
	for ; nextRound < from+basics.Round(parallelRequests); nextRound++ {
		// If the next round is not supported
		if s.nextRoundIsNotSupported(nextRound) {
			// We may get here when (1) The service starts
			// and gets to an unsupported round.  Since in
			// this loop we do not wait for the requests
			// to be written to the ledger, there is no
			// guarantee that the unsupported round will be
			// stopped in this case.

			// (2) The unsupported round is detected in the
			// "the rest" loop, but did not cancel because
			// the last supported round was not yet written
			// to the ledger.

			// It is sufficient to check only in the first
			// iteration, however checking in all in favor
			// of code simplicity.
			s.handleUnsupportedRound(nextRound)
			break
		}

		currentRoundComplete := make(chan bool, 2)
		// len(taskCh) + (# pending writes to completed) increases by 1
		taskCh <- s.pipelineCallback(nextRound, currentRoundComplete, recentReqs[len(recentReqs)-1], recentReqs[len(recentReqs)-int(seedLookback)], peerSelector)
		recentReqs = append(recentReqs[1:], currentRoundComplete)
	}

	completedRounds := make(map[basics.Round]bool)
	// the rest
	for {
		select {
		case round := <-completed:
			if round == 0 {
				// there was an error
				return
			}
			// if we're writing a catchpoint file, stop catching up to reduce the memory pressure. Once we finish writing the file we
			// could resume with the catchup.
			if s.ledger.IsWritingCatchpointFile() {
				s.log.Info("Catchup is stopping due to catchpoint file being written")
				s.suspendForCatchpointWriting = true
				return
			}
			completedRounds[round] = true
			// fetch rounds we can validate
			for completedRounds[nextRound-basics.Round(parallelRequests)] {
				// If the next round is not supported
				if s.nextRoundIsNotSupported(nextRound) {
					s.handleUnsupportedRound(nextRound)
					return
				}
				delete(completedRounds, nextRound)

				currentRoundComplete := make(chan bool, 2)
				// len(taskCh) + (# pending writes to completed) increases by 1
				taskCh <- s.pipelineCallback(nextRound, currentRoundComplete, recentReqs[len(recentReqs)-1], recentReqs[0], peerSelector)
				recentReqs = append(recentReqs[1:], currentRoundComplete)
				nextRound++
			}
		case <-s.ctx.Done():
			return
		}
	}
}

// periodicSync periodically asks the network for its latest round and syncs if we've fallen behind (also if our ledger stops advancing)
func (s *Service) periodicSync() {
	defer close(s.done)
	// if the catchup is disabled in the config file, just skip it.
	if s.parallelBlocks != 0 && !s.cfg.DisableNetworking {
		// The following request might be redundent, but it ensures we wait long enough for the DNS records to be loaded,
		// which are required for the sync operation.
		s.net.RequestConnectOutgoing(false, s.ctx.Done())
		s.sync()
	}
	stuckInARow := 0
	sleepDuration := s.deadlineTimeout
	for {
		currBlock := s.ledger.LastRound()
		select {
		case <-s.ctx.Done():
			return
		case <-s.ledger.Wait(currBlock + 1):
			// Ledger moved forward; likely to be by the agreement service.
			stuckInARow = 0
			// go to sleep for a short while, for a random duration.
			// we want to sleep for a random duration since it would "de-syncronize" us from the ledger advance sync
			sleepDuration = time.Duration(crypto.RandUint63()) % s.deadlineTimeout
			continue
		case <-time.After(sleepDuration):
			if sleepDuration < s.deadlineTimeout || s.cfg.DisableNetworking {
				sleepDuration = s.deadlineTimeout
				continue
			}
			// if the catchup is disabled in the config file, just skip it.
			if s.parallelBlocks == 0 {
				continue
			}
			// check to see if we're currently writing a catchpoint file. If so, wait longer before attempting again.
			if s.ledger.IsWritingCatchpointFile() {
				// keep the existing sleep duration and try again later.
				continue
			}
			s.suspendForCatchpointWriting = false
			s.log.Info("It's been too long since our ledger advanced; resyncing")
			s.sync()
		case cert := <-s.unmatchedPendingCertificates:
			// the agreement service has a valid certificate for a block, but not the block itself.
			if s.cfg.DisableNetworking {
				s.log.Warnf("the local node is missing block %d, however, the catchup would not be able to provide it when the network is disabled.", cert.Cert.Round)
				continue
			}
			s.syncCert(&cert)
		}

		if currBlock == s.ledger.LastRound() {
			stuckInARow++
		} else {
			stuckInARow = 0
		}
		if stuckInARow == s.cfg.CatchupFailurePeerRefreshRate {
			stuckInARow = 0
			// TODO: RequestConnectOutgoing in terms of Context
			s.net.RequestConnectOutgoing(true, s.ctx.Done())
		}
	}
}

// Syncs the client with the network. sync asks the network for last known block and tries to sync the system
// up the to the highest number it gets.
func (s *Service) sync() {
	// Only run sync once at a time
	// Store start time of sync - in NS so we can compute time.Duration (which is based on NS)
	start := time.Now()

	timeInNS := start.UnixNano()
	if !atomic.CompareAndSwapInt64(&s.syncStartNS, 0, timeInNS) {
		s.log.Infof("resuming previous sync from %d (now=%d)", atomic.LoadInt64(&s.syncStartNS), timeInNS)
	}

	pr := s.ledger.LastRound()

	s.log.EventWithDetails(telemetryspec.ApplicationState, telemetryspec.CatchupStartEvent, telemetryspec.CatchupStartEventDetails{
		StartRound: uint64(pr),
	})

	seedLookback := uint64(2)
	proto, err := s.ledger.ConsensusParams(pr)
	if err != nil {
		s.log.Errorf("catchup: could not get consensus parameters for round %v: %v", pr, err)
	} else {
		seedLookback = proto.SeedLookback
	}
	s.pipelinedFetch(seedLookback)

	initSync := false

	// if the catchupWriting flag is set, it means that we aborted the sync due to the ledger writing the catchup file.
	if !s.suspendForCatchpointWriting {
		// in that case, don't change the timer so that the "timer" would keep running.
		atomic.StoreInt64(&s.syncStartNS, 0)

		// close the initial sync channel if not already close
		if atomic.CompareAndSwapUint32(&s.initialSyncNotified, 0, 1) {
			close(s.InitialSyncDone)
			initSync = true
		}
	}

	elapsedTime := time.Now().Sub(start)
	s.log.EventWithDetails(telemetryspec.ApplicationState, telemetryspec.CatchupStopEvent, telemetryspec.CatchupStopEventDetails{
		StartRound: uint64(pr),
		EndRound:   uint64(s.ledger.LastRound()),
		Time:       elapsedTime,
		InitSync:   initSync,
	})
	s.log.Infof("Catchup Service: finished catching up, now at round %v (previously %v). Total time catching up %v.", s.ledger.LastRound(), pr, elapsedTime)
}

// syncCert retrieving a single round identified by the provided certificate and adds it to the ledger.
// The sync function attempts to keep trying to fetch the matching block or abort when the catchup service exits.
func (s *Service) syncCert(cert *PendingUnmatchedCertificate) {
	// we want to fetch a single round. no need to be concerned about lookback.
	s.fetchRound(cert.Cert, cert.VoteVerifier)
}

// TODO this doesn't actually use the digest from cert!
func (s *Service) fetchRound(cert agreement.Certificate, verifier *agreement.AsyncVoteVerifier) {
	blockHash := bookkeeping.BlockHash(cert.Proposal.BlockDigest) // semantic digest (i.e., hash of the block header), not byte-for-byte digest
	peerSelector := s.createPeerSelector(false)
	for s.ledger.LastRound() < cert.Round {
		peer, getPeerErr := peerSelector.GetNextPeer()
		if getPeerErr != nil {
			s.log.Debugf("fetchRound: was unable to obtain a peer to retrieve the block from")
			s.net.RequestConnectOutgoing(true, s.ctx.Done())
			continue
		}

		// Ask the fetcher to get the block somehow
		block, fetchedCert, _, err := s.innerFetch(cert.Round, peer)

		if err != nil {
			select {
			case <-s.ctx.Done():
				logging.Base().Debugf("fetchRound was asked to quit before we could acquire the block")
				return
			default:
			}
			logging.Base().Warnf("fetchRound could not acquire block, fetcher errored out: %v", err)
			peerSelector.RankPeer(peer, peerRankDownloadFailed)
			continue
		}

		if block.Hash() == blockHash && block.ContentsMatchHeader() {
			s.ledger.EnsureBlock(block, cert)
			return
		}
		// Otherwise, fetcher gave us the wrong block
		logging.Base().Warnf("fetcher gave us bad/wrong block (for round %d): fetched hash %v; want hash %v", cert.Round, block.Hash(), blockHash)
		peerSelector.RankPeer(peer, peerRankInvalidDownload)

		// As a failsafe, if the cert we fetched is valid but for the wrong block, panic as loudly as possible
		if cert.Round == fetchedCert.Round &&
			cert.Proposal.BlockDigest != fetchedCert.Proposal.BlockDigest &&
			fetchedCert.Authenticate(*block, s.ledger, verifier) == nil {
			s := "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
			s += "!!!!!!!!!! FORK DETECTED !!!!!!!!!!!\n"
			s += "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
			s += "fetchRound called with a cert authenticating block with hash %v.\n"
			s += "We fetched a valid cert authenticating a different block, %v. This indicates a fork.\n\n"
			s += "Cert from our agreement service:\n%#v\n\n"
			s += "Cert from the fetcher:\n%#v\n\n"
			s += "Block from the fetcher:\n%#v\n\n"
			s += "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
			s += "!!!!!!!!!! FORK DETECTED !!!!!!!!!!!\n"
			s += "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
			s = fmt.Sprintf(s, cert.Proposal.BlockDigest, fetchedCert.Proposal.BlockDigest, cert, fetchedCert, block)
			fmt.Println(s)
			logging.Base().Error(s)
		}
	}
}

// nextRoundIsNotSupported returns true if the next round upgrades to a protocol version
// which is not supported.
// In case of an error, it returns false
func (s *Service) nextRoundIsNotSupported(nextRound basics.Round) bool {
	lastLedgerRound := s.ledger.LastRound()
	supportedUpgrades := config.Consensus

	block, err := s.ledger.Block(lastLedgerRound)
	if err != nil {
		s.log.Errorf("nextRoundIsNotSupported: could not retrieve last block (%d) from the ledger : %v", lastLedgerRound, err)
		return false
	}
	bh := block.BlockHeader
	_, isSupportedUpgrade := supportedUpgrades[bh.NextProtocol]

	if bh.NextProtocolSwitchOn > 0 && !isSupportedUpgrade {
		// Save the last supported round number
		// It is not necessary to check bh.NextProtocolSwitchOn < s.lastSupportedRound
		// since there cannot be two protocol updates scheduled.
		s.lastSupportedRound = bh.NextProtocolSwitchOn - 1

		if nextRound >= bh.NextProtocolSwitchOn {
			return true
		}
	}
	return false
}

// handleUnSupportedRound receives a verified unsupported round: nextUnsupportedRound
// Checks if the last supported round was added to the ledger, and stops the service.
func (s *Service) handleUnsupportedRound(nextUnsupportedRound basics.Round) {

	s.log.Infof("Catchup Service: round %d is not approved. Service will stop once the last supported round is added to the ledger.",
		nextUnsupportedRound)

	// If the next round is an unsupported round, need to stop the
	// catchup service. Should stop after the last supported round
	// is added to the ledger.
	lr := s.ledger.LastRound()
	// Ledger writes are in order. >= guarantees last supported round is added to the ledger.
	if lr >= s.lastSupportedRound {
		s.log.Infof("Catchup Service: finished catching up to the last supported round %d. The subsequent rounds are not supported. Service is stopping.",
			lr)
		s.cancel()
	}
}

func (s *Service) createPeerSelector(pipelineFetch bool) *peerSelector {
	var peerClasses []peerClass
	if s.cfg.EnableCatchupFromArchiveServers {
		if pipelineFetch {
			if s.cfg.NetAddress != "" { // Relay node
				peerClasses = []peerClass{
					{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersConnectedOut},
					{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookArchivers},
					{initialRank: peerRankInitialThirdPriority, peerClass: network.PeersPhonebookRelays},
					{initialRank: peerRankInitialFourthPriority, peerClass: network.PeersConnectedIn},
				}
			} else {
				peerClasses = []peerClass{
					{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersPhonebookArchivers},
					{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersConnectedOut},
					{initialRank: peerRankInitialThirdPriority, peerClass: network.PeersPhonebookRelays},
				}
			}
		} else {
			if s.cfg.NetAddress != "" { // Relay node
				peerClasses = []peerClass{
					{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersConnectedOut},
					{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersConnectedIn},
					{initialRank: peerRankInitialThirdPriority, peerClass: network.PeersPhonebookRelays},
					{initialRank: peerRankInitialFourthPriority, peerClass: network.PeersPhonebookArchivers},
				}
			} else {
				peerClasses = []peerClass{
					{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersConnectedOut},
					{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays},
					{initialRank: peerRankInitialThirdPriority, peerClass: network.PeersPhonebookArchivers},
				}
			}
		}
	} else {
		if pipelineFetch {
			if s.cfg.NetAddress != "" { // Relay node
				peerClasses = []peerClass{
					{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersConnectedOut},
					{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays},
					{initialRank: peerRankInitialThirdPriority, peerClass: network.PeersConnectedIn},
				}
			} else {
				peerClasses = []peerClass{
					{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersConnectedOut},
					{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays},
				}
			}
		} else {
			if s.cfg.NetAddress != "" { // Relay node
				peerClasses = []peerClass{
					{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersConnectedOut},
					{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersConnectedIn},
					{initialRank: peerRankInitialThirdPriority, peerClass: network.PeersPhonebookRelays},
				}
			} else {
				peerClasses = []peerClass{
					{initialRank: peerRankInitialFirstPriority, peerClass: network.PeersConnectedOut},
					{initialRank: peerRankInitialSecondPriority, peerClass: network.PeersPhonebookRelays},
				}
			}
		}
	}
	return makePeerSelector(s.net, peerClasses)
}
