package apply

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAssetTransfer(t *testing.T) {
	// Creator
	secretSrc := keypair()
	src := basics.Address(secretSrc.SignatureVerifier)

	secretDst := keypair()
	dst := basics.Address(secretDst.SignatureVerifier)

	secretCls := keypair()
	cls := basics.Address(secretCls.SignatureVerifier)

	// prepare data
	var addrs = map[basics.Address]basics.AccountData{
		src: {
			MicroAlgos: basics.MicroAlgos{Raw: 10000000},
			AssetParams: map[basics.AssetIndex]basics.AssetParams{
				1: {Total: 1000000},
			},
			Assets: map[basics.AssetIndex]basics.AssetHolding{
				1: {Amount: 999500},
			},
		},
		dst: {
			MicroAlgos: basics.MicroAlgos{Raw: 10000000},
			Assets: map[basics.AssetIndex]basics.AssetHolding{
				1: {Amount: 500},
			},
		},
		cls: {
			MicroAlgos: basics.MicroAlgos{Raw: 10000000},
			Assets: map[basics.AssetIndex]basics.AssetHolding{
				1: {Amount: 0},
			},
		},
	}

	mockBal := mockBalances{protocol.ConsensusCurrentVersion, addrs}

	tx := transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:     dst,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     1,
			AssetAmount:   200,
			AssetReceiver: src,
			AssetCloseTo:  cls,
		},
	}
	var ad transactions.ApplyData
	err := AssetTransfer(tx.AssetTransferTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{FeeSink: feeSink}, &ad)
	require.NoError(t, err)

	require.Equal(t, uint64(300), ad.AssetClosingAmount)
	require.Equal(t, uint64(300), addrs[cls].Assets[1].Amount)
}
