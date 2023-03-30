package generator

import (
	"encoding/binary"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func (g *generator) makeTxnHeader(sender basics.Address, round, intra uint64) transactions.Header {
	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, uint64(g.txnCounter+intra))

	return transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: g.params.MinTxnFee},
		FirstValid:  basics.Round(round),
		LastValid:   basics.Round(round + 1000),
		GenesisID:   g.genesisID,
		GenesisHash: g.genesisHash,
		Note:        note,
	}
}

func (g *generator) makePaymentTxn(header transactions.Header, receiver basics.Address, amount uint64, closeRemainderTo basics.Address) transactions.Transaction {
	return transactions.Transaction{
		Type:   protocol.PaymentTx,
		Header: header,
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         receiver,
			Amount:           basics.MicroAlgos{Raw: amount},
			CloseRemainderTo: closeRemainderTo,
		},
	}
}

func (g *generator) makeAssetCreateTxn(header transactions.Header, total uint64, defaultFrozen bool, assetName string) transactions.Transaction {
	return transactions.Transaction{
		Type:   protocol.AssetConfigTx,
		Header: header,
		AssetConfigTxnFields: transactions.AssetConfigTxnFields{
			AssetParams: basics.AssetParams{
				Total:         total,
				DefaultFrozen: defaultFrozen,
				AssetName:     assetName,
				Manager:       header.Sender,
				Freeze:        header.Sender,
				Clawback:      header.Sender,
				Reserve:       header.Sender,
			},
		},
	}
}

func (g *generator) makeAssetDestroyTxn(header transactions.Header, index uint64) transactions.Transaction {
	return transactions.Transaction{
		Type:   protocol.AssetConfigTx,
		Header: header,
		AssetConfigTxnFields: transactions.AssetConfigTxnFields{
			ConfigAsset: basics.AssetIndex(index),
		},
	}
}

func (g *generator) makeAssetTransferTxn(header transactions.Header, receiver basics.Address, amount uint64, closeAssetsTo basics.Address, index uint64) transactions.Transaction {
	return transactions.Transaction{
		Type:   protocol.AssetTransferTx,
		Header: header,
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     basics.AssetIndex(index),
			AssetAmount:   amount,
			AssetReceiver: receiver,
			AssetCloseTo:  closeAssetsTo,
		},
	}
}

func (g *generator) makeAssetAcceptanceTxn(header transactions.Header, index uint64) transactions.Transaction {
	return g.makeAssetTransferTxn(header, header.Sender, 0, basics.Address{}, index)
}
