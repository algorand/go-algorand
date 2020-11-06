// Copyright (C) 2019-2020 Algorand, Inc.
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

package ledger

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

func makeString(len int) string {
	s := ""
	for i := 0; i < len; i++ {
		s += string(byte(i))
	}
	return s
}

func makeRandomStorageData(numEntries int) []storageData {
	currentConsensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	if numEntries < 0 {
		numEntries = maxEncodedAppStateEntries / 100
	}

	maxBytesLen := currentConsensusParams.MaxAppKeyLen
	if maxBytesLen > currentConsensusParams.MaxAppBytesValueLen {
		maxBytesLen = currentConsensusParams.MaxAppBytesValueLen
	}
	data := make([]storageData, numEntries)
	for idx := 0; idx < numEntries; idx++ {
		len := int(crypto.RandUint64() % uint64(maxBytesLen))
		var key []byte
		if len != 0 {
			key = make([]byte, len)
		}
		crypto.RandBytes(key)
		rndVal := crypto.RandUint64() % 2
		entry := storageData{
			Aidx:   uint64(idx),
			Global: rndVal == 0,
			Key:    key,
			Vtype:  rndVal + 1,
			Venc:   key,
		}
		data[idx] = entry
	}
	return data
}

func makeTestEncodedBalanceRecord(t *testing.T) encodedBalanceRecord {
	er := encodedBalanceRecord{}
	hash := crypto.Hash([]byte{1, 2, 3})
	copy(er.Address[:], hash[:])
	oneTimeSecrets := crypto.GenerateOneTimeSignatureSecrets(0, 1)
	vrfSecrets := crypto.GenerateVRFSecrets()
	ad := basics.AccountData{
		Status:             basics.NotParticipating,
		MicroAlgos:         basics.MicroAlgos{},
		RewardsBase:        0x1234123412341234,
		RewardedMicroAlgos: basics.MicroAlgos{},
		VoteID:             oneTimeSecrets.OneTimeSignatureVerifier,
		SelectionID:        vrfSecrets.PK,
		VoteFirstValid:     basics.Round(0x1234123412341234),
		VoteLastValid:      basics.Round(0x1234123412341234),
		VoteKeyDilution:    0x1234123412341234,
		AssetParams:        make(map[basics.AssetIndex]basics.AssetParams),
		Assets:             make(map[basics.AssetIndex]basics.AssetHolding),
		AuthAddr:           basics.Address(crypto.Hash([]byte{1, 2, 3, 4})),
	}
	currentConsensusParams := config.Consensus[protocol.ConsensusCurrentVersion]

	for assetCreatorAssets := 0; assetCreatorAssets < currentConsensusParams.MaxAssetsPerAccount; assetCreatorAssets++ {
		ap := basics.AssetParams{
			Total:         0x1234123412341234,
			Decimals:      0x12341234,
			DefaultFrozen: true,
			UnitName:      makeString(currentConsensusParams.MaxAssetUnitNameBytes),
			AssetName:     makeString(currentConsensusParams.MaxAssetNameBytes),
			URL:           makeString(currentConsensusParams.MaxAssetURLBytes),
			Manager:       basics.Address(crypto.Hash([]byte{1, byte(assetCreatorAssets)})),
			Reserve:       basics.Address(crypto.Hash([]byte{2, byte(assetCreatorAssets)})),
			Freeze:        basics.Address(crypto.Hash([]byte{3, byte(assetCreatorAssets)})),
			Clawback:      basics.Address(crypto.Hash([]byte{4, byte(assetCreatorAssets)})),
		}
		copy(ap.MetadataHash[:], makeString(32))
		ad.AssetParams[basics.AssetIndex(0x1234123412341234-assetCreatorAssets)] = ap
	}

	for assetHolderAssets := 0; assetHolderAssets < currentConsensusParams.MaxAssetsPerAccount; assetHolderAssets++ {
		ah := basics.AssetHolding{
			Amount: 0x1234123412341234,
			Frozen: true,
		}
		ad.Assets[basics.AssetIndex(0x1234123412341234-assetHolderAssets)] = ah
	}
	encodedAd, err := ad.MarshalMsg(nil)
	require.NoError(t, err)
	er.MiniAccountData = encodedAd
	er.StorageData = makeRandomStorageData(-1)
	return er
}

func TestStorageDataEncoding(t *testing.T) {
	ds := makeRandomStorageData(100)
	for _, data := range ds {
		enc, err := data.MarshalMsg(nil)
		require.NoError(t, err)

		var dec storageData
		_, err = dec.UnmarshalMsg(enc)
		require.NoError(t, err)
		require.Equal(t, data, dec)
	}
}

func TestEncodedBalanceRecordEncoding(t *testing.T) {
	er := makeTestEncodedBalanceRecord(t)
	encodedBr, err := er.MarshalMsg(nil)
	require.NoError(t, err)

	var er2 encodedBalanceRecord
	_, err = er2.UnmarshalMsg(encodedBr)
	require.NoError(t, err)

	require.Equal(t, er, er2)
}

func TestCatchpointFileBalancesChunkEncoding(t *testing.T) {
	fbc := catchpointFileBalancesChunk{}
	for i := 0; i < 512; i++ {
		fbc.Balances = append(fbc.Balances, makeTestEncodedBalanceRecord(t))
	}
	encodedFbc, err := fbc.MarshalMsg(nil)
	require.NoError(t, err)

	var fbc2 catchpointFileBalancesChunk
	_, err = fbc2.UnmarshalMsg(encodedFbc)
	require.NoError(t, err)

	require.Equal(t, fbc, fbc2)
}

func TestBasicCatchpointWriter(t *testing.T) {
	// create new protocol version, which has lower back balance.
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestBasicCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = 32
	protoParams.SeedLookback = 2
	protoParams.SeedRefreshInterval = 8
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectroy, _ := ioutil.TempDir(os.TempDir(), "catchpoints")
	defer func() {
		delete(config.Consensus, testProtocolVersion)
		os.RemoveAll(temporaryDirectroy)
	}()

	ml := makeMockLedgerForTracker(t, true)
	defer ml.close()
	ml.blocks = randomInitChain(testProtocolVersion, 10)
	accts := randomAccounts(300, false)

	au := &accountUpdates{}
	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au.initialize(conf, ".", protoParams, accts)
	defer au.close()
	err := au.loadFromDisk(ml)
	require.NoError(t, err)
	au.close()
	fileName := filepath.Join(temporaryDirectroy, "15.catchpoint")
	blocksRound := basics.Round(12345)
	blockHeaderDigest := crypto.Hash([]byte{1, 2, 3})
	catchpointLabel := fmt.Sprintf("%d#%v", blocksRound, blockHeaderDigest) // this is not a correct way to create a label, but it's good enough for this unit test

	readDb := ml.trackerDB().rdb
	err = readDb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		writer := makeCatchpointWriter(context.Background(), fileName, tx, blocksRound, blockHeaderDigest, catchpointLabel)
		for {
			more, err := writer.WriteStep(context.Background())
			require.NoError(t, err)
			if !more {
				break
			}
		}
		return
	})
	require.NoError(t, err)

	// load the file from disk.
	fileContent, err := ioutil.ReadFile(fileName)
	require.NoError(t, err)
	gzipReader, err := gzip.NewReader(bytes.NewBuffer(fileContent))
	require.NoError(t, err)
	tarReader := tar.NewReader(gzipReader)
	defer gzipReader.Close()
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			break
		}
		balancesBlockBytes := make([]byte, header.Size)
		readComplete := int64(0)

		for readComplete < header.Size {
			bytesRead, err := tarReader.Read(balancesBlockBytes[readComplete:])
			readComplete += int64(bytesRead)
			if err != nil {
				if err == io.EOF {
					if readComplete == header.Size {
						break
					}
					require.NoError(t, err)
				}
				break
			}
		}

		if header.Name == "content.msgpack" {
			var fileHeader CatchpointFileHeader
			err = protocol.Decode(balancesBlockBytes, &fileHeader)
			require.NoError(t, err)
			require.Equal(t, catchpointLabel, fileHeader.Catchpoint)
			require.Equal(t, blocksRound, fileHeader.BlocksRound)
			require.Equal(t, blockHeaderDigest, fileHeader.BlockHeaderDigest)
			require.Equal(t, uint64(len(accts)), fileHeader.TotalAccounts)
		} else if header.Name == "balances.1.1.msgpack" {
			var balances catchpointFileBalancesChunk
			err = protocol.Decode(balancesBlockBytes, &balances)
			require.NoError(t, err)
			require.Equal(t, uint64(len(accts)), uint64(len(balances.Balances)))
		} else {
			require.Failf(t, "unexpected tar chunk name %s", header.Name)
		}
	}
}

func TestFullCatchpointWriter(t *testing.T) {
	// create new protocol version, which has lower back balance.
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestFullCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.MaxBalLookback = 32
	protoParams.SeedLookback = 2
	protoParams.SeedRefreshInterval = 8
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectroy, _ := ioutil.TempDir(os.TempDir(), "catchpoints")
	defer func() {
		delete(config.Consensus, testProtocolVersion)
		os.RemoveAll(temporaryDirectroy)
	}()

	ml := makeMockLedgerForTracker(t, true)
	defer ml.close()
	ml.blocks = randomInitChain(testProtocolVersion, 10)
	accts := randomAccounts(BalancesPerCatchpointFileChunk*3, false)

	au := &accountUpdates{}
	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au.initialize(conf, ".", protoParams, accts)
	defer au.close()
	err := au.loadFromDisk(ml)
	require.NoError(t, err)
	au.close()
	fileName := filepath.Join(temporaryDirectroy, "15.catchpoint")
	blocksRound := basics.Round(12345)
	blockHeaderDigest := crypto.Hash([]byte{1, 2, 3})
	catchpointLabel := fmt.Sprintf("%d#%v", blocksRound, blockHeaderDigest) // this is not a correct way to create a label, but it's good enough for this unit test
	readDb := ml.trackerDB().rdb
	err = readDb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		writer := makeCatchpointWriter(context.Background(), fileName, tx, blocksRound, blockHeaderDigest, catchpointLabel)
		for {
			more, err := writer.WriteStep(context.Background())
			require.NoError(t, err)
			if !more {
				break
			}
		}
		return
	})
	require.NoError(t, err)

	// create a ledger.
	var initState InitState
	initState.Block.CurrentProtocol = protocol.ConsensusCurrentVersion
	l, err := OpenLedger(ml.log, "TestFullCatchpointWriter", true, initState, conf)
	require.NoError(t, err)
	defer l.Close()
	accessor := MakeCatchpointCatchupAccessor(l, l.log)

	err = accessor.ResetStagingBalances(context.Background(), true)
	require.NoError(t, err)

	// load the file from disk.
	fileContent, err := ioutil.ReadFile(fileName)
	require.NoError(t, err)
	gzipReader, err := gzip.NewReader(bytes.NewBuffer(fileContent))
	require.NoError(t, err)
	tarReader := tar.NewReader(gzipReader)
	var catchupProgress CatchpointCatchupAccessorProgress
	defer gzipReader.Close()
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			break
		}
		balancesBlockBytes := make([]byte, header.Size)
		readComplete := int64(0)

		for readComplete < header.Size {
			bytesRead, err := tarReader.Read(balancesBlockBytes[readComplete:])
			readComplete += int64(bytesRead)
			if err != nil {
				if err == io.EOF {
					if readComplete == header.Size {
						break
					}
					require.NoError(t, err)
				}
				break
			}
		}
		err = accessor.ProgressStagingBalances(context.Background(), header.Name, balancesBlockBytes, &catchupProgress)
		require.NoError(t, err)
	}

	err = l.trackerDBs.wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		err := applyCatchpointStagingBalances(ctx, tx, 0)
		return err
	})
	require.NoError(t, err)

	// verify that the account data aligns with what we originally stored :
	for addr, acct := range accts {
		// acctData, validThrough, err := l.LookupWithoutRewards(0, addr)
		acctData, err := l.FullLookup(0, addr)
		require.NoError(t, err)
		require.Equal(t, acct, acctData)
		// require.Equal(t, basics.Round(0), validThrough)
	}
}
