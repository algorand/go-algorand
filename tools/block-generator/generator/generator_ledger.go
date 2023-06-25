package generator

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/algorand/avm-abi/apps"
	"github.com/algorand/go-algorand/agreement"
	cconfig "github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	txn "github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
)

// ---- ledger simulation and introspection ----

func (g *generator) initializeLedger() uint64 {
	genBal := convertToGenesisBalances(g.balances)
	// add rewards pool with min balance
	genBal[g.rewardsPool] = basics.AccountData{
		MicroAlgos: basics.MicroAlgos{Raw: g.params.MinBalance},
	}
	bal := bookkeeping.MakeGenesisBalances(genBal, g.feeSink, g.rewardsPool)
	block, err := bookkeeping.MakeGenesisBlock(g.protocol, bal, g.genesisID, g.genesisHash)
	startingTxnCounter := block.TxnCounter
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
	l, err := ledger.OpenLedger(logging.Base(), prefix, true, ledgercore.InitState{
		Block:       block,
		Accounts:    bal.Balances,
		GenesisHash: g.genesisHash,
	}, cconfig.GetDefaultLocal())
	if err != nil {
		fmt.Printf("error initializing ledger: %v\n.", err)
		os.Exit(1)
	}
	g.ledger = l

	return startingTxnCounter
}

// ledgerAddBlock simulates ledger.AddBlock() but exposes the ApplyData
// calculated in BlockEvaluator.Eval() so that these can be added to the block.
// As opposed to the the real ledger.AddBlock() it also returns the number of 
// transactions observed in the block.
func (g *generator) ledgerAddBlock(blk bookkeeping.Block, cert agreement.Certificate) (uint64, error) {
	l := g.ledger
	// TODO: If we modify OpenLedger() to allow arbitrary tracers
	// we would be able to set adTracer := l.GetTracer()
	adTracer := eval.MakeApplyDataTracer(false /* nullTracer */)
	updates, err := eval.Eval(context.Background(), l, blk, false, nil, nil, adTracer)
	if err != nil {
		return 0, fmt.Errorf("ledgerAddBlock() failed: %w", err)
	}

	if adTracer.ApplyData != nil {
		if len(blk.Payset) != len(adTracer.ApplyData) {
			return 0, fmt.Errorf("ledgerAddBlock() failed: len(blk.Payset) (%d) != len(adTracer.ApplyData) (%d)", len(blk.Payset), len(adTracer.ApplyData))
		}
		for i := range blk.Payset {
			blk.Payset[i].ApplyData = adTracer.ApplyData[i]
		}
	}
	updates.OptimizeAllocatedMemory(4)

	vb := ledgercore.MakeValidatedBlock(blk, updates)

	txnCount := uint64(0)
	for _, sgnTxn := range blk.Payset {
		txnCount += 1 + uint64(len(sgnTxn.ApplyData.EvalDelta.InnerTxns))
	}

	return txnCount, l.AddValidatedBlock(vb, cert)
}

// introspectLedgerVsGenerator is only called when the --verbose command line argument is specified.
func (g *generator) introspectLedgerVsGenerator(roundNumber, intra uint64) (errs []error) {
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
		innerTxnCount += len(ad.EvalDelta.InnerTxns)
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
