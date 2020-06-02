package mocks

import (
	"fmt"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/node/indexer"
	"github.com/algorand/go-algorand/protocol"
)

type MockNode struct {
	ledger    *data.Ledger
	genesisID string
}

func MakeMockNode(ledger *data.Ledger, genesisID string) MockNode {
	return MockNode{ledger: ledger, genesisID: genesisID}
}

func (m MockNode) Ledger() *data.Ledger {
	return m.ledger
}

func (m MockNode) Status() (s node.StatusReport, err error) {
	s = node.StatusReport{
		LastRound:   basics.Round(1),
		LastVersion: protocol.ConsensusCurrentVersion,
	}
	return
}
func (m MockNode) GenesisID() string {
	return m.genesisID
}

func (m MockNode) GenesisHash() crypto.Digest {
	return m.ledger.GenesisHash()
}

func (m MockNode) BroadcastSignedTxGroup(txgroup []transactions.SignedTxn) error {
	return nil
}

func (m MockNode) GetPendingTransaction(txID transactions.Txid) (res node.TxnWithStatus, found bool) {
	res = node.TxnWithStatus{}
	found = true
	return
}

func (m MockNode) GetPendingTxnsFromPool() ([]transactions.SignedTxn, error) {
	return nil, nil
}

func (m MockNode) SuggestedFee() basics.MicroAlgos {
	return basics.MicroAlgos{Raw: 1}
}

func (m MockNode) StartCatchup(catchpoint string) error {
	return nil
}

func (m MockNode) AbortCatchup(catchpoint string) error {
	return nil
}

// unused by handlers:
func (m MockNode) Config() config.Local {
	return config.GetDefaultLocal()
}
func (m MockNode) Start() {}

func (m MockNode) ListeningAddress() (string, bool) {
	return "mock listening addresses not implemented", false
}

func (m MockNode) Stop() {}

func (m MockNode) ListTxns(addr basics.Address, minRound basics.Round, maxRound basics.Round) ([]node.TxnWithStatus, error) {
	return nil, fmt.Errorf("listtxns not implemented")
}

func (m MockNode) GetTransaction(addr basics.Address, txID transactions.Txid, minRound basics.Round, maxRound basics.Round) (node.TxnWithStatus, bool) {
	return node.TxnWithStatus{}, false
}

func (m MockNode) PoolStats() node.PoolStats {
	return node.PoolStats{}
}

func (m MockNode) IsArchival() bool {
	return false
}

func (m MockNode) Indexer() (*indexer.Indexer, error) {
	return nil, fmt.Errorf("indexer not implemented")
}

func (m MockNode) GetTransactionByID(txid transactions.Txid, rnd basics.Round) (node.TxnWithStatus, error) {
	return node.TxnWithStatus{}, fmt.Errorf("get transaction by id not implemented")
}
