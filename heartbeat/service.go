// Copyright (C) 2019-2024 Algorand, Inc.
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

package heartbeat

import (
	"context"
	"sync"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// Service emits keep-alive heartbeats for accts that are in danger of
// suspension.
type Service struct {
	// addresses that should be monitored for suspension
	accts participants
	// current status and balances
	ledger ledger
	// where to send the heartbeats
	bcast txnBroadcaster

	// infrastructure
	ctx      context.Context
	shutdown context.CancelFunc
	wg       sync.WaitGroup
	log      logging.Logger
}

// NewService creates a heartbeat service. It will need to know which accounts
// to emit heartbeats for, and how to create the heartbeats.
func NewService(accts participants, ledger ledger, bcast txnBroadcaster, log logging.Logger) *Service {
	return &Service{
		accts:  accts,
		ledger: ledger,
		bcast:  bcast,
		log:    log.With("Context", "heartbeat"),
	}
}

// Start starts the goroutines for the Service.
func (s *Service) Start() {
	s.ctx, s.shutdown = context.WithCancel(context.Background())
	s.wg.Add(1)
	s.log.Info("starting heartbeat service")
	go s.loop()
}

// Stop any goroutines associated with this worker.
func (s *Service) Stop() {
	s.log.Debug("heartbeat service is stopping")
	defer s.log.Debug("heartbeat service has stopped")
	s.shutdown()
	s.wg.Wait()
}

// findChallenged() returns a list of accounts that need a heartbeat because
// they have been challenged.
func (s *Service) findChallenged(rules config.ProposerPayoutRules) []account.ParticipationRecordForRound {
	current := s.ledger.LastRound()

	ch := apply.FindChallenge(rules, current, s.ledger, apply.ChRisky)
	if ch.IsZero() {
		return nil
	}

	var found []account.ParticipationRecordForRound
	for _, pr := range s.accts.Keys(current + 1) { // only look at accounts we have part keys for
		acct, _, _, err := s.ledger.LookupAccount(current, pr.Account)
		if err != nil {
			s.log.Errorf("error looking up %v: %v", pr.Account, err)
			continue
		}
		if acct.Status == basics.Online {
			if ch.Failed(pr.Account, acct.LastSeen()) {
				s.log.Infof(" %v needs a heartbeat\n", pr.Account)
				found = append(found, pr)
			}
		}
		/* If we add a grace period to suspension for absenteeism, then we could
		   also make it free to heartbeat during that period. */
	}
	return found
}

// loop monitors for any of Service's participants being suspended. If they are,
// it tries to being them back online by emitting a heartbeat transaction. It
// could try to predict an upcoming suspension, which would prevent the
// suspension from ever occurring, but that would be considerably more complex
// both to avoid emitting repeated heartbeats, and to ensure the prediction and
// the suspension logic match.  This feels like a cleaner end-to-end test, at
// the cost of lost couple rounds of participation. (Though suspension is
// designed to be extremely unlikely anyway.)
func (s *Service) loop() {
	defer s.wg.Done()
	latest := s.ledger.LastRound()
	for {
		// exit if Done, else wait for next round
		select {
		case <-s.ctx.Done():
			return
		case <-s.ledger.WaitMem(latest + 1):
		}

		latest = s.ledger.LastRound()

		lastHdr, err := s.ledger.BlockHdr(latest)
		if err != nil {
			s.log.Errorf("heartbeat service could not fetch block header for round %d: %v", latest, err)
			continue // Try again next round, I guess?
		}
		proto := config.Consensus[lastHdr.CurrentProtocol]

		for _, pr := range s.findChallenged(proto.Payouts) {
			stxn := s.prepareHeartbeat(pr, lastHdr)
			s.log.Infof("sending heartbeat %v for %v\n", stxn.Txn.HeartbeatTxnFields, pr.Account)
			err = s.bcast.BroadcastInternalSignedTxGroup([]transactions.SignedTxn{stxn})
			if err != nil {
				s.log.Errorf("error broadcasting heartbeat %v for %v: %v", stxn, pr.Account, err)
			}
		}
	}
}

// acceptingByteCode is the byte code to a logic signature that will accept anything (except rekeying).
var acceptingByteCode = logic.MustAssemble(`
#pragma version 11
txn RekeyTo; global ZeroAddress; ==
`)
var acceptingSender = basics.Address(logic.HashProgram(acceptingByteCode))

func (s *Service) prepareHeartbeat(pr account.ParticipationRecordForRound, latest bookkeeping.BlockHeader) transactions.SignedTxn {
	var stxn transactions.SignedTxn
	stxn.Lsig = transactions.LogicSig{Logic: acceptingByteCode}
	stxn.Txn.Type = protocol.HeartbeatTx
	stxn.Txn.Header = transactions.Header{
		Sender:      acceptingSender,
		FirstValid:  latest.Round + 1,
		LastValid:   latest.Round + 1 + 100, // maybe use the grace period?
		GenesisHash: latest.GenesisHash,
	}

	id := basics.OneTimeIDForRound(stxn.Txn.LastValid, pr.KeyDilution)
	stxn.Txn.HeartbeatTxnFields = transactions.HeartbeatTxnFields{
		HbAddress: pr.Account,
		HbProof:   pr.Voting.Sign(id, latest.Seed),
		HbSeed:    latest.Seed,
	}

	return stxn
}