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

package txnsync

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/bloom"
	"github.com/algorand/go-algorand/util/timers"
)

func BenchmarkTxidToUint64(b *testing.B) {
	txID := transactions.Txid{1, 2, 3, 4, 5}
	for i := 0; i < b.N; i++ {
		txidToUint64(txID)
	}
}

func TestBloomFallback(t *testing.T) {
	genesisHash := crypto.Hash([]byte("gh"))
	genesisID := "gID"

	txnGroups := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			GroupTransactionID: transactions.Txid{1},
			Transactions: []transactions.SignedTxn{
				{
					Txn: transactions.Transaction{
						Type: protocol.PaymentTx,
						Header: transactions.Header{
							Sender:      basics.Address(crypto.Hash([]byte("2"))),
							Fee:         basics.MicroAlgos{Raw: 100},
							GenesisHash: genesisHash,
						},
						PaymentTxnFields: transactions.PaymentTxnFields{
							Receiver: basics.Address(crypto.Hash([]byte("4"))),
							Amount:   basics.MicroAlgos{Raw: 1000},
						},
					},
					Sig: crypto.Signature{1},
				},
			},
		},
		transactions.SignedTxGroup{
			GroupTransactionID: transactions.Txid{2},
			Transactions: []transactions.SignedTxn{
				{
					Txn: transactions.Transaction{
						Type: protocol.PaymentTx,
						Header: transactions.Header{
							Sender:      basics.Address(crypto.Hash([]byte("1"))),
							Fee:         basics.MicroAlgos{Raw: 100},
							GenesisHash: genesisHash,
							GenesisID:   genesisID,
						},
						PaymentTxnFields: transactions.PaymentTxnFields{
							Receiver: basics.Address(crypto.Hash([]byte("2"))),
							Amount:   basics.MicroAlgos{Raw: 1000},
						},
					},
					Sig: crypto.Signature{2},
				},
				{
					Txn: transactions.Transaction{
						Type: protocol.KeyRegistrationTx,
						Header: transactions.Header{
							Sender:      basics.Address(crypto.Hash([]byte("1"))),
							GenesisHash: genesisHash,
							GenesisID:   genesisID,
						},
					},
					Sig: crypto.Signature{3},
				},
			},
		},
		transactions.SignedTxGroup{
			GroupTransactionID: transactions.Txid{3},
			Transactions: []transactions.SignedTxn{
				{
					Txn: transactions.Transaction{
						Type: protocol.AssetConfigTx,
						Header: transactions.Header{
							Sender:      basics.Address(crypto.Hash([]byte("1"))),
							Fee:         basics.MicroAlgos{Raw: 100},
							GenesisHash: genesisHash,
						},
					},
					Sig: crypto.Signature{4},
				},
				{
					Txn: transactions.Transaction{
						Type: protocol.AssetFreezeTx,
						Header: transactions.Header{
							Sender:      basics.Address(crypto.Hash([]byte("1"))),
							GenesisHash: genesisHash,
						},
					},
					Sig: crypto.Signature{5},
				},
				{
					Txn: transactions.Transaction{
						Type: protocol.CompactCertTx,
						Header: transactions.Header{
							Sender:      basics.Address(crypto.Hash([]byte("1"))),
							GenesisHash: genesisHash,
						},
					},
					Msig: crypto.MultisigSig{Version: 1},
				},
			},
		},
	}

	var s syncState
	s.node = &justRandomFakeNode{}
	var encodingParams requestParams

	encodingParams.Modulator = 1

	bf := s.makeBloomFilter(encodingParams, txnGroups, nil)
	switch bf.filter.(type) {
	case *bloom.Filter:
		t.Errorf("expected xorfilter but got classic bloom filter")
	case *bloom.XorFilter:
		// ok
	case *bloom.XorFilter8:
		// ok
	default:
		panic("unknown internal bloom filter object")
	}

	// Duplicate first entry. xorfilter can't handle duplicates. We _probably_ never have duplicate txid prefixes when we grab the first 8 bytes of 32 bytes, but that's not 100%, maybe only 99.999999%
	stg := txnGroups[0]
	txnGroups = append(txnGroups, stg)

	bf = s.makeBloomFilter(encodingParams, txnGroups, nil)
	switch bf.filter.(type) {
	case *bloom.Filter:
		// ok
	case *bloom.XorFilter:
		t.Errorf("expected bloom filter but got xor")
	case *bloom.XorFilter8:
		t.Errorf("expected bloom filter but got xor")
	default:
		panic("unknown internal bloom filter object")
	}
}

type justRandomFakeNode struct {
}

func (fn *justRandomFakeNode) Events() <-chan Event { return nil }

func (fn *justRandomFakeNode) GetCurrentRoundSettings() (out RoundSettings) { return }

func (fn *justRandomFakeNode) Clock() (out timers.WallClock) { return }

func (fn *justRandomFakeNode) Random(rng uint64) uint64 {
	var xb [8]byte
	rand.Read(xb[:])
	rv := binary.LittleEndian.Uint64(xb[:])
	return rv % rng
}

func (fn *justRandomFakeNode) GetPeers() []PeerInfo { return nil }

func (fn *justRandomFakeNode) GetPeer(interface{}) (out PeerInfo) { return }

func (fn *justRandomFakeNode) UpdatePeers(txsyncPeers []*Peer, netPeers []interface{}, peersAverageDataExchangeRate uint64) {
}
func (fn *justRandomFakeNode) SendPeerMessage(netPeer interface{}, msg []byte, callback SendMessageCallback) {
}
func (fn *justRandomFakeNode) GetPendingTransactionGroups() (txGroups []transactions.SignedTxGroup, latestLocallyOriginatedGroupCounter uint64) {
	return
}
func (fn *justRandomFakeNode) IncomingTransactionGroups(peer *Peer, messageSeq uint64, txGroups []transactions.SignedTxGroup) (transactionPoolSize int) {
	return 0
}
func (fn *justRandomFakeNode) NotifyMonitor() chan struct{} { return nil }
