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

package generator

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/algorand/avm-abi/apps"
	cconfig "github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	txn "github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/rpcs"
)

// ---- ledger block generation ----

func (g *generator) setBlockHeader(cert *rpcs.EncodedBlockCert) {
	cert.Block.BlockHeader = bookkeeping.BlockHeader{
		Round:          basics.Round(g.round),
		TxnCounter:     g.txnCounter,
		Branch:         bookkeeping.BlockHash{},
		Seed:           committee.Seed{},
		TxnCommitments: bookkeeping.TxnCommitments{NativeSha512_256Commitment: crypto.Digest{}},
		TimeStamp:      g.timestamp,
		GenesisID:      g.genesisID,
		GenesisHash:    g.genesisHash,
		RewardsState: bookkeeping.RewardsState{
			FeeSink:                   g.feeSink,
			RewardsPool:               g.rewardsPool,
			RewardsLevel:              0,
			RewardsRate:               0,
			RewardsResidue:            0,
			RewardsRecalculationRound: 0,
		},
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: g.protocol,
		},
		UpgradeVote:        bookkeeping.UpgradeVote{},
		StateProofTracking: nil,
	}
}

// ---- ledger simulation and introspection ----

// initializeLedger creates a new ledger
func (g *generator) initializeLedger() {
	genBal := convertToGenesisBalances(g.balances)
	// add rewards pool with min balance
	genBal[g.rewardsPool] = basics.AccountData{
		MicroAlgos: basics.MicroAlgos{Raw: g.params.MinBalance},
	}
	bal := bookkeeping.MakeGenesisBalances(genBal, g.feeSink, g.rewardsPool)
	block, err := bookkeeping.MakeGenesisBlock(g.protocol, bal, g.genesisID, g.genesisHash)
	if err != nil {
		fmt.Printf("error making genesis: %v\n.", err)
		os.Exit(1)
	}
	var prefix string
	if g.genesisID == "" {
		prefix = "block-generator"
	} else {
		prefix = g.genesisID
	}
	l, err := ledger.OpenLedger(g.log, prefix, true, ledgercore.InitState{
		Block:       block,
		Accounts:    bal.Balances,
		GenesisHash: g.genesisHash,
	}, cconfig.GetDefaultLocal())
	if err != nil {
		fmt.Printf("error initializing ledger: %v\n.", err)
		os.Exit(1)
	}
	g.ledger = l
}

func (g *generator) minTxnsForBlock(round uint64) uint64 {
	// There are no transactions in the 0th round
	if round == 0 {
		return 0
	}
	return g.config.TxnPerBlock
}

// startRound updates the generator's txnCounter based on the latest block header's counter.
// It is assumed that g.round has already been incremented in finishRound()
func (g *generator) startRound() error {
	var latestRound basics.Round
	if g.round > 0 {
		latestRound = basics.Round(g.round - 1)
	} else {
		latestRound = basics.Round(0)
	}

	latestHeader, err := g.ledger.BlockHdr(latestRound)
	if err != nil {
		return fmt.Errorf("could not obtain block header for round %d (latest round %d): %w", g.round, latestRound, err)
	}

	g.txnCounter = latestHeader.TxnCounter
	return nil
}

// finishRound tells the generator it can apply any pending state and updates its round
func (g *generator) finishRound() {
	g.timestamp += consensusTimeMilli
	g.round++

	// Apply pending assets...
	g.assets = append(g.assets, g.pendingAssets...)
	g.pendingAssets = nil

	g.latestPaysetWithExpectedID = nil
	g.latestData = make(map[TxTypeID]uint64)

	for kind, pendingAppSlice := range g.pendingAppSlice {
		for _, pendingApp := range pendingAppSlice {
			appID := pendingApp.appID
			if g.appMap[kind][appID] == nil {
				g.appSlice[kind] = append(g.appSlice[kind], pendingApp)
				g.appMap[kind][appID] = pendingApp
				for sender := range pendingApp.optins {
					g.accountAppOptins[kind][sender] = append(g.accountAppOptins[kind][sender], appID)
				}
			} else { // just union the optins when already exists
				for sender := range pendingApp.optins {
					g.appMap[kind][appID].optins[sender] = true
					g.accountAppOptins[kind][sender] = append(g.accountAppOptins[kind][sender], appID)
				}
			}
		}
	}
	g.resetPendingApps()
}

// ---- ledger block evaluator ----

func (g *generator) startEvaluator(hdr bookkeeping.BlockHeader, paysetHint int) (*eval.BlockEvaluator, error) {
	return eval.StartEvaluator(g.ledger, hdr,
		eval.EvaluatorOptions{
			PaysetHint:          paysetHint,
			Generate:            true,
			Validate:            false,
			MaxTxnBytesPerBlock: 0,
			Tracer:              nil,
		})
}

func (g *generator) evaluateBlock(hdr bookkeeping.BlockHeader, txGroups [][]txn.SignedTxnWithAD, paysetHint int) (*ledgercore.ValidatedBlock, uint64 /* txnCount */, time.Duration /* commit wait time */, error) {
	commitWaitTime := time.Duration(0)
	waitDelay := 10 * time.Millisecond
	eval, err := g.startEvaluator(hdr, paysetHint)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("could not start evaluator: %w", err)
	}
	for i, txGroup := range txGroups {
		for {
			txErr := eval.TransactionGroup(txGroup)
			if txErr != nil {
				if strings.Contains(txErr.Error(), "database table is locked") {
					time.Sleep(waitDelay)
					commitWaitTime += waitDelay
					// sometimes the database is locked, so we retry
					continue
				}
				return nil, 0, 0, fmt.Errorf("could not evaluate transaction group %d: %w", i, txErr)
			}
			break
		}
	}
	ub, err := eval.GenerateBlock(nil)
	lvb := ledgercore.MakeValidatedBlock(ub.UnfinishedBlock(), ub.UnfinishedDeltas())
	return &lvb, eval.TestingTxnCounter(), commitWaitTime, err
}

func countInners(ad txn.ApplyData) int {
	result := 0
	for _, itxn := range ad.EvalDelta.InnerTxns {
		result += 1 + countInners(itxn.ApplyData)
	}
	return result
}

// introspectLedgerVsGenerator is only called when the --verbose command line argument is specified.
func (g *generator) introspectLedgerVsGenerator(roundNumber, intra uint64) (errs []error) {
	if !g.verbose {
		errs = append(errs, fmt.Errorf("introspectLedgerVsGenerator called when verbose=false"))
	}

	round := basics.Round(roundNumber)
	block, err := g.ledger.Block(round)
	if err != nil {
		round = err.(ledgercore.ErrNoEntry).Committed
		fmt.Printf("WARNING: inconsistent generator v. ledger state. Reset round=%d: %v\n", round, err)
		errs = append(errs, err)
	}

	payset := block.Payset
	nonEmptyApplyDataIndices := make([]uint64, 0)
	emptyAd := txn.ApplyData{}
	innerTxnCount := 0
	for i, sgnTxn := range payset {
		ad := sgnTxn.ApplyData
		if ad.Equal(emptyAd) {
			continue
		}
		nonEmptyApplyDataIndices = append(nonEmptyApplyDataIndices, uint64(i))
		innerTxnCount += countInners(ad)
	}

	ledgerStateDeltas, err := g.ledger.GetStateDeltaForRound(round)
	if err != nil {
		errs = append(errs, err)
	}

	cumulative := CumulativeEffects(g.reportData)

	sum := uint64(0)
	for effect, cnt := range cumulative {
		if TxTypeID(effect) == genesis {
			continue
		}
		sum += cnt
	}
	fmt.Print("--------------------\n")
	fmt.Printf("roundNumber (generator): %d\n", roundNumber)
	fmt.Printf("round (ledger): %d\n", round)
	fmt.Printf("g.txnCounter + intra: %d\n", g.txnCounter+intra)
	fmt.Printf("block.BlockHeader.TxnCounter: %d\n", block.BlockHeader.TxnCounter)
	fmt.Printf("len(g.latestPaysetWithExpectedID): %d\n", len(g.latestPaysetWithExpectedID))
	fmt.Printf("len(block.Payset): %d\n", len(payset))
	fmt.Printf("len(nonEmptyApplyDataIndices): %d\n", len(nonEmptyApplyDataIndices))
	fmt.Printf("innerTxnCount: %d\n", innerTxnCount)
	fmt.Printf("g.latestData: %+v\n", g.latestData)
	fmt.Printf("cumuluative : %+v\n", cumulative)
	fmt.Printf("all txn sum: %d\n", sum)
	fmt.Print("--------------------\n")

	// ---- FROM THE LEDGER: box and createable evidence ---- //

	ledgerBoxEvidenceCount := 0
	ledgerBoxEvidence := make(map[uint64][]uint64)
	boxes := ledgerStateDeltas.KvMods
	for k := range boxes {
		appID, nameIEsender, _ := apps.SplitBoxKey(k)
		ledgerBoxEvidence[appID] = append(ledgerBoxEvidence[appID], binary.LittleEndian.Uint64([]byte(nameIEsender))-1)
		ledgerBoxEvidenceCount++
	}

	// TODO: can get richer info about app-Creatables from:
	// updates.Accts.AppResources
	ledgerCreatableAppsEvidence := make(map[uint64]uint64)
	for creatableID, creatable := range ledgerStateDeltas.Creatables {
		if creatable.Ctype == basics.AppCreatable {
			ledgerCreatableAppsEvidence[uint64(creatableID)] = accountToIndex(creatable.Creator)
		}
	}
	fmt.Printf("ledgerBoxEvidenceCount: %d\n", ledgerBoxEvidenceCount)
	fmt.Printf("ledgerCreatableAppsEvidence: %d\n", len(ledgerCreatableAppsEvidence))

	// ---- FROM THE GENERATOR: expected created and optins ---- //

	expectedCreated := map[appKind]map[uint64]uint64{
		appKindBoxes: make(map[uint64]uint64),
		appKindSwap:  make(map[uint64]uint64),
	}
	expectedOptins := map[appKind]map[uint64]map[uint64]bool{
		appKindBoxes: make(map[uint64]map[uint64]bool),
		appKindSwap:  make(map[uint64]map[uint64]bool),
	}

	expectedOptinsCount := 0
	for kind, appMap := range g.pendingAppMap {
		for appID, ad := range appMap {
			if len(ad.optins) > 0 {
				expectedOptins[kind][appID] = ad.optins
				expectedOptinsCount += len(ad.optins)
			} else {
				expectedCreated[kind][appID] = ad.sender
			}
		}
	}
	fmt.Printf("expectedCreatedCount: %d\n", len(expectedCreated[appKindBoxes]))
	fmt.Printf("expectedOptinsCount: %d\n", expectedOptinsCount)

	// ---- COMPARE LEDGER AND GENERATOR EVIDENCE ---- //

	ledgerCreatablesUnexpected := map[uint64]uint64{}
	for creatableID, creator := range ledgerCreatableAppsEvidence {
		if expectedCreated[appKindSwap][creatableID] != creator && expectedCreated[appKindBoxes][creatableID] != creator {
			ledgerCreatablesUnexpected[creatableID] = creator
		}
	}
	generatorExpectedCreatablesNotFound := map[uint64]uint64{}
	for creatableID, creator := range expectedCreated[appKindBoxes] {
		if ledgerCreatableAppsEvidence[creatableID] != creator {
			generatorExpectedCreatablesNotFound[creatableID] = creator
		}
	}

	ledgerBoxOptinsUnexpected := map[uint64][]uint64{}
	for appId, boxOptins := range ledgerBoxEvidence {
		for _, optin := range boxOptins {
			if _, ok := expectedOptins[appKindBoxes][appId][optin]; !ok {
				ledgerBoxOptinsUnexpected[appId] = append(ledgerBoxOptinsUnexpected[appId], optin)
			}
		}
	}

	generatorExpectedOptinsNotFound := map[uint64][]uint64{}
	for appId, appOptins := range expectedOptins[appKindBoxes] {
		for optin := range appOptins {
			missing := true
			for _, boxOptin := range ledgerBoxEvidence[appId] {
				if boxOptin == optin {
					missing = false
					break
				}
			}
			if missing {
				generatorExpectedOptinsNotFound[appId] = append(generatorExpectedOptinsNotFound[appId], optin)
			}
		}
	}

	fmt.Printf("ledgerCreatablesUnexpected: %+v\n", ledgerCreatablesUnexpected)
	fmt.Printf("generatorExpectedCreatablesNotFound: %+v\n", generatorExpectedCreatablesNotFound)
	fmt.Printf("ledgerBoxOptinsUnexpected: %+v\n", ledgerBoxOptinsUnexpected)
	fmt.Printf("expectedOptinsNotFound: %+v\n", generatorExpectedOptinsNotFound)
	return errs
}
