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
	er.AccountData = encodedAd
	return er
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
	defer func() {
		delete(config.Consensus, testProtocolVersion)
		os.RemoveAll("./catchpoints")
	}()

	ml := makeMockLedgerForTracker(t)
	defer ml.close()
	ml.blocks = randomInitChain(testProtocolVersion, 10)
	accts := []map[basics.Address]basics.AccountData{randomAccounts(300)}

	au := &accountUpdates{}
	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au.initialize(conf, ".", protoParams, accts[0])
	defer au.close()
	err := au.loadFromDisk(ml)
	require.NoError(t, err)
	au.close()
	fileName := filepath.Join("./catchpoints", "15.catchpoint")
	blocksRound := basics.Round(12345)
	blockHeaderDigest := crypto.Hash([]byte{1, 2, 3})
	catchpointLabel := fmt.Sprintf("%d#%v", blocksRound, blockHeaderDigest) // this is not a correct way to create a label, but it's good enough for this unit test
	writer := makeCatchpointWriter(fileName, ml.trackerDB().rdb, blocksRound, blockHeaderDigest, catchpointLabel)
	for {
		more, err := writer.WriteStep(context.Background())
		require.NoError(t, err)
		if !more {
			break
		}
	}

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
			var fileHeader catchpointFileHeader
			err = protocol.Decode(balancesBlockBytes, &fileHeader)
			require.NoError(t, err)
			require.Equal(t, catchpointLabel, fileHeader.Catchpoint)
			require.Equal(t, blocksRound, fileHeader.BlocksRound)
			require.Equal(t, blockHeaderDigest, fileHeader.BlockHeaderDigest)
			require.Equal(t, uint64(len(accts[0])), fileHeader.TotalAccounts)
		} else if header.Name == "balances.1.1.msgpack" {
			var balances catchpointFileBalancesChunk
			err = protocol.Decode(balancesBlockBytes, &balances)
			require.NoError(t, err)
			require.Equal(t, uint64(len(accts[0])), uint64(len(balances.Balances)))
		} else {
			require.Failf(t, "unexpected tar chunk name %s", header.Name)
		}
	}
}
