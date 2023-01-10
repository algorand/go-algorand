package algotrust

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/network"
)

type DummyLedgerForAlgoTrust struct {
	badHdr bool
}

type dummySender struct {
}

func (ds *dummySender) GetAddress() string {
	return "aaa"
}

func (dl *DummyLedgerForAlgoTrust) RegisterBlockListeners(list []ledgercore.BlockListener) {
}

func TestAlgoTrust(t *testing.T) {

	dl := DummyLedgerForAlgoTrust{}
	at := MakeAlgoTrust(&dl)

	rmsg := network.IncomingMessage{}
	rmsg.Sender = &dummySender{}

	stxn := transactions.SignedTxn{}
	stxn.Sig = crypto.Signature{1}

	drop, msg := at.PreprocessTxnFiltering(rmsg)
	require.False(t, drop)
	require.Equal(t, network.OutgoingMessage{}, msg)

	drop, msg = at.PreprocessTxnFiltering(rmsg)
	require.True(t, drop)
	require.Equal(t, msg, network.OutgoingMessage{Action: network.Disconnect})

	at.RecordTxnsaction(&stxn, rmsg.Sender)

	blk := &bookkeeping.Block{}
	blk.Payset = make([]transactions.SignedTxnInBlock, 1, 1)
	blk.Payset[0].SignedTxnWithAD = transactions.SignedTxnWithAD{SignedTxn: stxn}
	at.nbw.OnNewBlock(*blk, ledgercore.StateDelta{})

	for x := 0; x < 1000; x++ {
		drop, msg = at.PreprocessTxnFiltering(rmsg)
		if drop == false {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.False(t, drop)
	require.Equal(t, network.OutgoingMessage{}, msg)

	drop, msg = at.PreprocessTxnFiltering(rmsg)
	require.False(t, drop)
	require.Equal(t, network.OutgoingMessage{}, msg)

	drop, msg = at.PreprocessTxnFiltering(rmsg)
	require.True(t, drop)
	require.Equal(t, msg, network.OutgoingMessage{Action: network.Disconnect})
}
