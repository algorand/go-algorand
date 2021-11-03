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
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/pooldata"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/bloom"
	"github.com/algorand/go-algorand/util/timers"
)

func getTxnGroups(genesisHash crypto.Digest, genesisID string) []pooldata.SignedTxGroup {
	return []pooldata.SignedTxGroup{
		pooldata.SignedTxGroup{
			GroupCounter:       0,
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
		pooldata.SignedTxGroup{
			GroupCounter:       1,
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
		pooldata.SignedTxGroup{
			GroupCounter:       2,
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
}

func BenchmarkTxidToUint64(b *testing.B) {
	txID := transactions.Txid{1, 2, 3, 4, 5}
	for i := 0; i < b.N; i++ {
		txidToUint64(txID)
	}
}

const testingGenesisID = "gID"

var testingGenesisHash = crypto.Hash([]byte("gh"))

func TestBloomFallback(t *testing.T) {
	partitiontest.PartitionTest(t)

	var s syncState
	s.node = &justRandomFakeNode{}
	var encodingParams requestParams

	for encodingParams.Modulator = 1; encodingParams.Modulator < 3; encodingParams.Modulator++ {
		txnGroups := getTxnGroups(testingGenesisHash, testingGenesisID)
		bf := s.makeBloomFilter(encodingParams, txnGroups, nil, nil)

		switch bloomFilterType(bf.encoded.BloomFilterType) {
		case multiHashBloomFilter:
			t.Errorf("expected xorfilter but got classic bloom filter")
		case xorBloomFilter32:
			// ok
		case xorBloomFilter8:
			t.Errorf("expected xorBloomFilter32 but got xorBloomFilter8")
		default:
			t.Errorf("unknown internal bloom filter object : %d", bloomFilterType(bf.encoded.BloomFilterType))
		}

		// Duplicate first entry. xorfilter can't handle
		// duplicates. We _probably_ never have duplicate txid
		// prefixes when we grab the first 8 bytes of 32 bytes, but
		// that's not 100%, maybe only 99.999999%
		stg := txnGroups[1]
		txnGroups = append(txnGroups, stg)

		bf = s.makeBloomFilter(encodingParams, txnGroups, nil, nil)
		switch bloomFilterType(bf.encoded.BloomFilterType) {
		case multiHashBloomFilter:
			// ok
		case xorBloomFilter32:
			t.Errorf("expected bloom filter but got xor")
		case xorBloomFilter8:
			t.Errorf("expected bloom filter but got xor")
		default:
			t.Errorf("unknown internal bloom filter object : %d", bloomFilterType(bf.encoded.BloomFilterType))
		}
	}
}

// TestHint tests that the hint is used only when it should be used
func TestHint(t *testing.T) {
	partitiontest.PartitionTest(t)

	var s syncState
	s.node = &justRandomFakeNode{}
	var encodingParams requestParams
	defaultFilterType := xorBloomFilter32

	for encodingParams.Modulator = 1; encodingParams.Modulator < 3; encodingParams.Modulator++ {
		txnGroups := getTxnGroups(testingGenesisHash, testingGenesisID)
		bf := s.makeBloomFilter(encodingParams, txnGroups, nil, nil)

		switch bloomFilterType(bf.encoded.BloomFilterType) {
		case xorBloomFilter32:
			// ok
		default:
			require.Fail(t, "expect xorBloomFilter32")
		}
		require.Equal(t, defaultFilterType, bloomFilterType(bf.encoded.BloomFilterType))

		// Change the filter of bf to other than the default filter i.e. XorFilter8
		bf.encoded.BloomFilterType = byte(xorBloomFilter8)

		// Pass bf as a hint.
		bf2 := s.makeBloomFilter(encodingParams, txnGroups, nil, &bf)

		// If the filter of bf2 is not defaultFilterType (i.e. is XorFilter8), then the hint was used.
		// The hint must be used, and the filter should not be the default filter.
		require.NotEqual(t, defaultFilterType, bf2.encoded.BloomFilterType)
		switch bloomFilterType(bf2.encoded.BloomFilterType) {
		case xorBloomFilter8:
			// ok
		default:
			require.Fail(t, "expect xorBloomFilter8")
		}

		// Now change txnGroups, so that the hint will not be used
		for i := range txnGroups {
			txnGroups[i].GroupCounter += uint64(len(txnGroups))
		}
		bf2 = s.makeBloomFilter(encodingParams, txnGroups, nil, &bf)

		// If the filter of bf2 is XorFilter (i.e. defaultFilterType), then the hint was not used
		switch bloomFilterType(bf2.encoded.BloomFilterType) {
		case xorBloomFilter32:
			// ok
		default:
			require.Fail(t, "expect xorBloomFilter32")
		}
		require.Equal(t, defaultFilterType, bloomFilterType(bf2.encoded.BloomFilterType))
	}
}

// TestEncodingDecoding checks the encoding/decoding of the filters
func TestEncodingDecoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	var s syncState
	s.node = &justRandomFakeNode{}

	filters := []func(int, *syncState) (filter bloom.GenericFilter, filterType bloomFilterType){
		filterFactoryXor8, filterFactoryXor32, filterFactoryBloom}

	var randomEntries [10]transactions.Txid
	for i := range randomEntries {
		crypto.RandBytes(randomEntries[i][:])
	}
	var err error
	var testableBf *testableBloomFilter
	var remarshaled []byte
	// For each filter type
	for _, ff := range filters {

		filter, filterType := ff(len(randomEntries), &s)
		for i := range randomEntries {
			filter.Set(randomEntries[i][:])
		}
		var enc encodedBloomFilter
		enc.BloomFilterType = byte(filterType)
		enc.BloomFilter, err = filter.MarshalBinary()
		require.NoError(t, err)

		testableBf, err = decodeBloomFilter(enc)
		require.NoError(t, err)

		remarshaled, err = testableBf.filter.MarshalBinary()

		require.NoError(t, err)
		require.Equal(t, enc.BloomFilter, remarshaled)
	}
}

func TestDecodingErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	bf, err := decodeBloomFilter(encodedBloomFilter{})
	require.Equal(t, errInvalidBloomFilterEncoding, err)
	require.Equal(t, (*testableBloomFilter)(nil), bf)

	var ebf encodedBloomFilter
	ebf.BloomFilterType = byte(multiHashBloomFilter)
	_, err = decodeBloomFilter(ebf)

	require.Error(t, err)
}

func TestBloomFilterTest(t *testing.T) {
	partitiontest.PartitionTest(t)

	filters := []func(int, *syncState) (filter bloom.GenericFilter, filterType bloomFilterType){
		filterFactoryXor8, filterFactoryXor32, filterFactoryBloom}

	for _, ff := range filters {

		var s syncState
		s.node = &justRandomFakeNode{}
		var err error
		txnGroups := getTxnGroups(testingGenesisHash, testingGenesisID)

		filter, filterType := ff(len(txnGroups), &s)
		for _, txnGroup := range txnGroups {
			filter.Set(txnGroup.GroupTransactionID[:])
		}
		var enc encodedBloomFilter
		enc.BloomFilterType = byte(filterType)
		enc.BloomFilter, err = filter.MarshalBinary()
		require.NoError(t, err)

		testableBf, err := decodeBloomFilter(enc)
		require.NoError(t, err)

		for testableBf.encodingParams.Modulator = 0; testableBf.encodingParams.Modulator < 7; testableBf.encodingParams.Modulator++ {
			for testableBf.encodingParams.Offset = 0; testableBf.encodingParams.Offset < testableBf.encodingParams.Modulator; testableBf.encodingParams.Offset++ {
				for _, tx := range txnGroups {
					ans := testableBf.test(tx.GroupTransactionID)
					expected := true
					if testableBf.encodingParams.Modulator > 1 {
						if txidToUint64(tx.GroupTransactionID)%uint64(testableBf.encodingParams.Modulator) != uint64(testableBf.encodingParams.Offset) {
							expected = false
						}
					}
					require.Equal(t, expected, ans)
				}
			}
		}
	}

}

func BenchmarkTestBloomFilter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()

		var s syncState
		s.node = &justRandomFakeNode{}
		var err error
		txnGroups, _, _, _ := txnGroupsData(300)
		for j := range txnGroups {
			txnGroups[j].GroupTransactionID = txnGroups[j].Transactions.ID()
		}

		testableBfs := make([]*testableBloomFilter, 0)

		for j := 0; j < 150; j++ {
			filter, filterType := filterFactoryXor32(len(txnGroups), &s)
			for _, txnGroup := range txnGroups {
				filter.Set(txnGroup.GroupTransactionID[:])
			}
			var enc encodedBloomFilter
			enc.BloomFilterType = byte(filterType)
			enc.BloomFilter, err = filter.MarshalBinary()
			require.NoError(b, err)

			testableBf, err := decodeBloomFilter(enc)
			require.NoError(b, err)

			testableBfs = append(testableBfs, testableBf)
		}

		b.StartTimer()

		for _, tx := range txnGroups {
			for _, testableBf := range testableBfs {
					testableBf.test(tx.GroupTransactionID)
					//ans := testableBf.test(tx.GroupTransactionID)
					//expected := true
					//if testableBf.encodingParams.Modulator > 1 {
					//	if txidToUint64(tx.GroupTransactionID)%uint64(testableBf.encodingParams.Modulator) != uint64(testableBf.encodingParams.Offset) {
					//		expected = false
					//	}
					//}
					//if ans != expected {
					//	fmt.Println("???")
					//}
				}
		}
	}
}

type justRandomFakeNode struct {
}

func (fn *justRandomFakeNode) Events() <-chan Event { return nil }

func (fn *justRandomFakeNode) ProposalFilterCh() <-chan crypto.Digest { return nil }

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

func (fn *justRandomFakeNode) GetPeerLatency(netPeer interface{}) time.Duration {
	return 0
}

func (fn *justRandomFakeNode) GetPendingTransactionGroups() (txGroups []pooldata.SignedTxGroup, latestLocallyOriginatedGroupCounter uint64) {
	return
}
func (fn *justRandomFakeNode) IncomingTransactionGroups(peer *Peer, messageSeq uint64, txGroups []pooldata.SignedTxGroup) (transactionPoolSize int) {
	return 0
}
func (fn *justRandomFakeNode) NotifyMonitor() chan struct{} { return nil }

func (fn *justRandomFakeNode) RelayProposal(proposalBytes []byte, txnSlices []pooldata.SignedTxnSlice) {
}

func (fn *justRandomFakeNode) HandleProposalMessage(proposalDataBytes []byte, txGroups []pooldata.SignedTxGroup, peer *Peer) {
}
