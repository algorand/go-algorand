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

package pools

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type poolVotingAccountsFunc func(basics.Round) []basics.Address

func (f poolVotingAccountsFunc) VotingAccountsForRound(r basics.Round) []basics.Address {
	return f(r)
}

type poolGenerationTracer struct {
	logic.NullEvalTracer
	generated int
}

func (tr *poolGenerationTracer) AfterBlock(*bookkeeping.BlockHeader) {
	tr.generated++
}

func makeGenerationTestPool(t testing.TB, version protocol.ConsensusVersion, count int, lastValid basics.Round) (*TransactionPool, []basics.Address) {
	t.Helper()
	secrets, addresses := generateAccounts(2)
	l := mockLedger(t, initAccFixed(addresses, 1<<50), version)
	t.Cleanup(l.Close)
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = max(cfg.TxPoolSize, count+1)
	pool := MakeTransactionPool(l, cfg, logging.TestingLog(t), poolVotingAccountsFunc(func(basics.Round) []basics.Address { return nil }))
	for i := 0; i < count; i++ {
		tx := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender: addresses[0], Fee: basics.MicroAlgos{Raw: 20000},
				LastValid: lastValid, GenesisHash: l.GenesisHash(),
				Note: []byte(fmt.Sprintf("payment %d", i)),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{Receiver: addresses[1], Amount: basics.MicroAlgos{Raw: 1}},
		}
		require.NoError(t, pool.rememberOne(tx.Sign(secrets[0])))
	}
	return pool, addresses
}

func TestPoolSpeculativeBlockGeneration(t *testing.T) {
	partitiontest.PartitionTest(t)
	// No t.Parallel: the small block limit exercises overflow without thousands of transactions.
	version := protocol.ConsensusVersion(t.Name())
	params := proto
	params.MaxTxnBytesPerBlock = 1500
	config.Consensus[version] = params
	t.Cleanup(func() { delete(config.Consensus, version) })

	for _, tc := range []struct {
		name    string
		count   int
		timeout bool
		reason  string
	}{
		{"empty", 0, false, telemetryspec.AssembleBlockEmpty},
		{"partial", 2, false, telemetryspec.AssembleBlockEmpty},
		{"full", 30, false, telemetryspec.AssembleBlockFull},
		{"timeout", 2, true, telemetryspec.AssembleBlockTimeout},
	} {
		for _, supplier := range []string{"noKeys", "voting", "unspecified"} {
			t.Run(tc.name+"/"+supplier, func(t *testing.T) {
				pool, addresses := makeGenerationTestPool(t, version, tc.count, 1000)
				require.True(t, pool.assemblyResults.skipped, "constructor should not generate a block without keys")
				require.Nil(t, pool.assemblyResults.blk)
				queries := 0
				pool.vac = poolVotingAccountsFunc(func(r basics.Round) []basics.Address {
					queries++
					require.Equal(t, basics.Round(1), r)
					if supplier == "voting" {
						return addresses[:1]
					}
					return nil
				})
				if supplier == "unspecified" {
					pool.vac = nil
				}
				tracer := &poolGenerationTracer{}
				pool.evalTracer = tracer
				if tc.timeout {
					pool.assemblyDeadline = time.Now().Add(-time.Second)
				}
				before := pool.PendingTxIDs()
				fee := pool.FeePerByte()
				pool.mu.Lock()
				pool.recomputeBlockEvaluator(nil, 0, false)
				pool.mu.Unlock()
				require.ElementsMatch(t, before, pool.PendingTxIDs())
				require.Equal(t, fee, pool.FeePerByte())
				require.Equal(t, tc.count, pool.pendingBlockEvaluator.PaySetSize())
				if tc.name == "full" {
					require.Positive(t, pool.numPendingWholeBlocks)
				}
				if supplier != "unspecified" {
					require.Equal(t, 1, queries, "participation is sampled once per recomputation")
				}
				if supplier == "noKeys" {
					require.Zero(t, tracer.generated)
					require.Nil(t, pool.assemblyResults.blk)
					return
				}
				require.Equal(t, 1, tracer.generated)
				require.NoError(t, pool.assemblyResults.err)
				require.NotNil(t, pool.assemblyResults.blk)
				require.Equal(t, tc.reason, pool.assemblyResults.stats.StopReason)
				if supplier == "voting" {
					require.True(t, pool.assemblyResults.blk.ContainsAddress(addresses[0]))
				}
			})
		}
	}
}

func TestPoolParticipationChanges(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	pool, addresses := makeGenerationTestPool(t, protocol.ConsensusCurrentVersion, 3, 2)
	tracer := &poolGenerationTracer{}
	pool.evalTracer = tracer

	// Install keys after this round was skipped. An explicit request returns
	// a usable empty block containing the newly installed proposer's account.
	pool.vac = poolVotingAccountsFunc(func(r basics.Round) []basics.Address {
		if r <= 2 {
			return addresses[:1]
		}
		return nil // keys expire before round 3
	})
	pool.logAssembleStats = true // also exercise telemetry's nonnil-block assumption
	blk, err := pool.AssembleBlock(1, time.Now().Add(time.Second))
	require.NoError(t, err)
	require.NotNil(t, blk)
	require.Empty(t, blk.UnfinishedBlock().Payset)
	require.True(t, blk.ContainsAddress(addresses[0]))
	require.True(t, pool.assemblyDeadline.IsZero())
	require.Zero(t, tracer.generated)

	// Another node commits one transaction in round 1. Local round 2 should
	// resume generation, retaining just the two uncommitted transactions.
	eval := newBlockEvaluator(t, pool.ledger)
	require.NoError(t, eval.TransactionGroup(pool.PendingTxGroups()[0][0].WithAD()))
	committed, err := eval.GenerateBlock(addresses[:1])
	require.NoError(t, err)
	block := committed.FinishBlock(committee.Seed{}, addresses[0], false)
	require.NoError(t, pool.ledger.AddBlock(block, agreement.Certificate{}))
	pool.OnNewBlock(block, committed.UnfinishedDeltas())
	require.Len(t, pool.PendingTxGroups(), 2)
	require.Equal(t, 1, tracer.generated)
	require.False(t, pool.assemblyResults.skipped)
	require.Len(t, pool.assemblyResults.blk.UnfinishedBlock().Payset, 2)

	// An empty round 2 leaves those transactions to expire. Pool maintenance
	// must still remove them even though round 3 has no possible proposers.
	eval = newBlockEvaluator(t, pool.ledger)
	committed, err = eval.GenerateBlock(addresses[:1])
	require.NoError(t, err)
	block = committed.FinishBlock(committee.Seed{}, addresses[0], false)
	require.NoError(t, pool.ledger.AddBlock(block, agreement.Certificate{}))
	pool.OnNewBlock(block, committed.UnfinishedDeltas())
	require.Empty(t, pool.PendingTxGroups())
	require.True(t, pool.assemblyResults.skipped)
	require.Equal(t, 1, tracer.generated)
	pool.Reset()
	require.True(t, pool.assemblyResults.skipped)
	require.Equal(t, 1, tracer.generated)
}

func TestPoolDevModeForcesGeneration(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	pool, _ := makeGenerationTestPool(t, protocol.ConsensusCurrentVersion, 3, 1000)
	tracer := &poolGenerationTracer{}
	pool.evalTracer = tracer
	blk, err := pool.AssembleDevModeBlock()
	require.NoError(t, err)
	require.NotNil(t, blk)
	require.Len(t, blk.UnfinishedBlock().Payset, 3)
	require.Equal(t, 1, tracer.generated)
	require.False(t, pool.assemblyResults.skipped)
	pool.mu.Lock()
	pool.recomputeBlockEvaluator(nil, 0, false)
	pool.mu.Unlock()
	require.True(t, pool.assemblyResults.skipped, "forcing dev-mode assembly must not persist")
	require.Equal(t, 1, tracer.generated)
}

func TestPoolSkippedAssemblyWakesWaiter(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	pool, addresses := makeGenerationTestPool(t, protocol.ConsensusCurrentVersion, 0, 1000)
	committed, err := pool.assembleEmptyBlock(1)
	require.NoError(t, err)
	block := committed.FinishBlock(committee.Seed{}, addresses[0], false)
	require.NoError(t, pool.ledger.AddBlock(block, agreement.Certificate{}))

	// Agreement can ask for round 2 before OnNewBlock has prepared it.
	done := make(chan struct{})
	var assembled bookkeeping.Block
	var assemblyErr error
	go func() {
		defer close(done)
		blk, err := pool.AssembleBlock(2, time.Now().Add(10*time.Second))
		assemblyErr = err
		if blk != nil {
			assembled = blk.UnfinishedBlock()
		}
	}()
	// If an assertion fails, wait for the bounded assembly request before closing the ledger.
	t.Cleanup(func() { <-done })
	require.Eventually(t, func() bool {
		pool.assemblyMu.Lock()
		defer pool.assemblyMu.Unlock()
		return pool.assemblyRound == 2
	}, 5*time.Second, time.Millisecond)

	pool.OnNewBlock(block, committed.UnfinishedDeltas())
	select {
	case <-done:
		require.NoError(t, assemblyErr)
		require.Equal(t, basics.Round(2), assembled.Round())
		require.Empty(t, assembled.Payset)
	case <-time.After(5 * time.Second):
		t.Fatal("skipping generation did not wake the assembly request")
	}
}

func TestPoolSkippedAssemblyAllowsRecompute(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	pool, addresses := makeGenerationTestPool(t, protocol.ConsensusCurrentVersion, 0, 1000)
	committed, err := pool.assembleEmptyBlock(1)
	require.NoError(t, err)
	block := committed.FinishBlock(committee.Seed{}, addresses[0], false)

	// Pause the fallback after its evaluator has started, while it is loading
	// possible proposers. Recomputing the next round must still be able to finish.
	fallbackStarted := make(chan struct{})
	continueFallback := make(chan struct{})
	releaseFallback := sync.OnceFunc(func() { close(continueFallback) })
	pool.vac = poolVotingAccountsFunc(func(r basics.Round) []basics.Address {
		if r == 1 {
			close(fallbackStarted)
			<-continueFallback
		}
		return nil
	})
	assemblyDone := make(chan struct{})
	var assemblyErr error
	var returnedBlock bool
	go func() {
		defer close(assemblyDone)
		blk, err := pool.AssembleBlock(1, time.Now().Add(10*time.Second))
		assemblyErr, returnedBlock = err, blk != nil
	}()
	t.Cleanup(func() { releaseFallback(); <-assemblyDone })
	select {
	case <-fallbackStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("assembly did not start its fallback")
	}

	require.NoError(t, pool.ledger.AddBlock(block, agreement.Certificate{}))
	recomputeDone := make(chan struct{})
	go func() {
		defer close(recomputeDone)
		pool.OnNewBlock(block, committed.UnfinishedDeltas())
	}()
	t.Cleanup(func() { releaseFallback(); <-recomputeDone })
	select {
	case <-recomputeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("fallback held the assembly mutex and blocked recomputation")
	}

	releaseFallback()
	<-assemblyDone
	require.ErrorIs(t, assemblyErr, ErrStaleBlockAssemblyRequest)
	require.False(t, returnedBlock, "must discard the fallback after the pool advances")
	require.True(t, pool.assemblyDeadline.IsZero())
}

func TestPoolAssemblyTimeoutClearsDeadline(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	pool, _ := makeGenerationTestPool(t, protocol.ConsensusCurrentVersion, 3, 1000)
	pool.vac = nil
	pool.assemblyResults = poolAsmResults{roundStartedEvaluating: 1}
	blk, err := pool.AssembleBlock(1, time.Now().Add(-time.Second))
	require.NoError(t, err)
	require.NotNil(t, blk)
	require.Empty(t, blk.UnfinishedBlock().Payset)
	require.True(t, pool.assemblyDeadline.IsZero())
	pool.mu.Lock()
	pool.recomputeBlockEvaluator(nil, 0, false)
	pool.mu.Unlock()
	blk, err = pool.AssembleBlock(1, time.Now().Add(time.Second))
	require.NoError(t, err)
	require.Len(t, blk.UnfinishedBlock().Payset, 3)
}

// BenchmarkPoolBlockGeneration compares actual pool recomputation with and
// without speculative generation, keeping transaction evaluation in both cases.
func BenchmarkPoolBlockGeneration(b *testing.B) {
	for _, count := range []int{0, 1000, 10000} {
		for _, generate := range []bool{true, false} {
			b.Run(fmt.Sprintf("txns=%d/generate=%t", count, generate), func(b *testing.B) {
				pool, _ := makeGenerationTestPool(b, protocol.ConsensusCurrentVersion, count, 1000)
				if generate {
					pool.vac = nil
				}
				b.ReportAllocs()
				for b.Loop() {
					pool.mu.Lock()
					pool.recomputeBlockEvaluator(nil, 0, false)
					pool.mu.Unlock()
				}
				require.Equal(b, count, pool.PendingCount())
			})
		}
	}
}
