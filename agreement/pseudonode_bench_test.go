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

package agreement

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
)

// slowBlockFactory adds a fixed delay to AssembleBlock to simulate the cost
// of assembling a real block from the transaction pool.
type slowBlockFactory struct {
	BlockFactory
	delay time.Duration
}

func (f slowBlockFactory) AssembleBlock(r basics.Round, addrs []basics.Address) (UnfinishedBlock, error) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return f.BlockFactory.AssembleBlock(r, addrs)
}

// makeProposalsOldStyle recreates the pre-filterProposers behaviour: it
// calls AssembleBlock unconditionally and then iterates over all accounts.
// This is the baseline that the new makeProposals (with filterProposers)
// optimises.
func (n asyncPseudonode) makeProposalsOldStyle(round basics.Round, period period, accounts []account.ParticipationRecordForRound) ([]proposal, []unauthenticatedVote) {
	addresses := make([]basics.Address, len(accounts))
	for i := range accounts {
		addresses[i] = accounts[i].Account
	}
	ve, err := n.factory.AssembleBlock(round, addresses)
	if err != nil {
		if err != ErrAssembleBlockRoundStale {
			n.log.Errorf("pseudonode.makeProposalsOldStyle: could not generate a proposal for round %d: %v", round, err)
		}
		return nil, nil
	}

	votes := make([]unauthenticatedVote, 0, len(accounts))
	proposals := make([]proposal, 0, len(accounts))
	for _, acc := range accounts {
		payload, proposal, pErr := proposalForBlock(acc.Account, acc.VRF, ve, period, n.ledger)
		if pErr != nil {
			continue
		}

		rv := rawVote{Sender: acc.Account, Round: round, Period: period, Step: propose, Proposal: proposal}
		uv, vErr := makeVote(rv, acc.VotingSigner(), acc.VRF, n.ledger)
		if vErr != nil {
			continue
		}

		proposals = append(proposals, payload)
		votes = append(votes, uv)
	}

	return proposals, votes
}

// buildFilterBenchNode creates an asyncPseudonode ready for proposal
// benchmarking.  If tamperAllVrf is true, every accounts SelectionID in the
// ledger is replaced with a mismatched VRF key so that filterProposers finds
// no eligible accounts.
func buildFilterBenchNode(b *testing.B, numAccounts int, slowAssemble time.Duration, tamperAllVrf bool) (*asyncPseudonode, []account.ParticipationRecordForRound) {
	b.Helper()

	rootSeed := sha256.Sum256([]byte(b.Name()))
	accounts, balances := createTestAccountsAndBalances(b, numAccounts, rootSeed[:])

	if tamperAllVrf {
		for addr := range balances {
			differentVrf := generatePseudoRandomVRF(len(balances) + 999)
			bd := balances[addr]
			bd.SelectionID = differentVrf.PK
			balances[addr] = bd
		}
	}

	ledger := makeTestLedger(balances)
	sLogger := serviceLogger{logging.NewLogger()}
	sLogger.SetLevel(logging.Error) // silence warn/error logs during benchmarks

	km := makeRecordingKeyManager(accounts)
	pn := &asyncPseudonode{
		factory:   slowBlockFactory{BlockFactory: testBlockFactory{Owner: 0}, delay: slowAssemble},
		validator: testBlockValidator{},
		keys:      km,
		ledger:    ledger,
		log:       sLogger,
		monitor:   nil,
	}

	round := ledger.NextRound()
	partKeys := pn.loadRoundParticipationKeys(round)
	if len(partKeys) == 0 {
		b.Fatal("no participation keys loaded")
	}
	return pn, partKeys
}

// BenchmarkFilterProposers measures the cost of the VRF credential check that
// filterProposers performs on every account.  This is the overhead the new
// code pays each round to determine whether any account is elected.
//
// On Apple M2 Pro, typical results:
//
//	1 account   ~0.26 ms/op
//	5 accounts  ~1.28 ms/op
//	10 accounts ~2.55 ms/op
//	50 accounts ~12.76 ms/op
func BenchmarkFilterProposers(b *testing.B) {
	for _, n := range []int{1, 5, 10, 50} {
		b.Run(fmt.Sprintf("%daccounts", n), func(b *testing.B) {
			pn, partKeys := buildFilterBenchNode(b, n, 0, false)
			round := pn.ledger.NextRound()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pn.filterProposers(round, period(i%10), partKeys)
			}
		})
	}
}

// BenchmarkMakeProposals_OldStyle_NotElected simulates the pre-branch
// behaviour when no accounts are elected to propose: AssembleBlock is called
// unconditionally, paying its full cost, even though all vote credentials
// will ultimately fail verification.
//
// Mismatched VRF keys ensure filterProposers (if it existed) would return
// empty, making this a direct measurement of the waste eliminated by the
// optimisation.
func BenchmarkMakeProposals_OldStyle_NotElected(b *testing.B) {
	for _, delay := range []time.Duration{1 * time.Millisecond, 10 * time.Millisecond} {
		b.Run(fmt.Sprintf("AssembleDelay_%s", delay), func(b *testing.B) {
			pn, partKeys := buildFilterBenchNode(b, 10, delay, true)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pn.makeProposalsOldStyle(pn.ledger.NextRound(), period(i%5), partKeys)
			}
		})
	}
}

// BenchmarkMakeProposals_NewStyle_NotElected shows the new behaviour when
// no accounts are elected: filterProposers determines this inexpensively
// (no AssembleBlock call), and makeProposals returns immediately.
//
// Compare this against BenchmarkMakeProposals_OldStyle_NotElected to see
// the speedup: new style takes only the filterProposers cost (see
// BenchmarkFilterProposers/10accounts), while old style also pays the
// full AssembleBlock delay.
func BenchmarkMakeProposals_NewStyle_NotElected(b *testing.B) {
	for _, delay := range []time.Duration{1 * time.Millisecond, 10 * time.Millisecond} {
		b.Run(fmt.Sprintf("AssembleDelay_%s", delay), func(b *testing.B) {
			pn, partKeys := buildFilterBenchNode(b, 10, delay, true)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pn.makeProposals(pn.ledger.NextRound(), period(i%5), partKeys)
			}
		})
	}
}

// BenchmarkMakeProposals_Elected measures the (small) overhead that
// filterProposers adds when accounts ARE elected: the filter still pays
// a VRF credential check per account, then proceeds with AssembleBlock
// and the rest of the pipeline.
//
// With 1 account holding 100% of the stake, election is essentially
// deterministic (P(weight=0) ≈ e⁻²⁰), so we get a stable measurement.
func BenchmarkMakeProposals_Elected(b *testing.B) {
	for _, delay := range []time.Duration{1 * time.Millisecond, 10 * time.Millisecond} {
		for _, n := range []int{1, 5, 10} {
			b.Run(fmt.Sprintf("AssembleDelay_%s/%daccounts", delay, n), func(b *testing.B) {
				pn, partKeys := buildFilterBenchNode(b, n, delay, false)

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					pn.makeProposals(pn.ledger.NextRound(), period(i%5), partKeys)
				}
			})
		}
	}
}
