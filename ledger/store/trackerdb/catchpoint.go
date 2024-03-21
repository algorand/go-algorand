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

package trackerdb

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// TrieMemoryConfig is the memory configuration setup used for the merkle trie.
var TrieMemoryConfig = merkletrie.MemoryConfig{
	NodesCountPerPage:         MerkleCommitterNodesPerPage,
	CachedNodesCount:          TrieCachedNodesCount,
	PageFillFactor:            0.95,
	MaxChildrenPagesThreshold: 64,
}

// MerkleCommitterNodesPerPage controls how many nodes will be stored in a single page
// value was calibrated using BenchmarkCalibrateNodesPerPage
var MerkleCommitterNodesPerPage = int64(116)

// TrieCachedNodesCount defines how many balances trie nodes we would like to keep around in memory.
// value was calibrated using BenchmarkCalibrateCacheNodeSize
var TrieCachedNodesCount = 9000

// CatchpointDirName represents the directory name in which all the catchpoints files are stored
var CatchpointDirName = "catchpoints"

// CatchpointState is used to store catchpoint related variables into the catchpointstate table.
//
//msgp:ignore CatchpointState
type CatchpointState string

const (
	// CatchpointStateLastCatchpoint is written by a node once a catchpoint label is created for a round
	CatchpointStateLastCatchpoint = CatchpointState("lastCatchpoint")
	// CatchpointStateWritingFirstStageInfo state variable is set to 1 if catchpoint's first stage is unfinished,
	// and is 0 otherwise. Used to clear / restart the first stage after a crash.
	// This key is set in the same db transaction as the account updates, so the
	// unfinished first stage corresponds to the current db round.
	CatchpointStateWritingFirstStageInfo = CatchpointState("writingFirstStageInfo")
	// CatchpointStateWritingCatchpoint if there is an unfinished catchpoint, this state variable is set to
	// the catchpoint's round. Otherwise, it is set to 0.
	// DEPRECATED.
	CatchpointStateWritingCatchpoint = CatchpointState("writingCatchpoint")
	// CatchpointStateCatchupState is the state of the catchup process. The variable is stored only during the catchpoint catchup process, and removed afterward.
	CatchpointStateCatchupState = CatchpointState("catchpointCatchupState")
	// CatchpointStateCatchupLabel is the label to which the currently catchpoint catchup process is trying to catchup to.
	CatchpointStateCatchupLabel = CatchpointState("catchpointCatchupLabel")
	// CatchpointStateCatchupBlockRound is the block round that is associated with the current running catchpoint catchup.
	CatchpointStateCatchupBlockRound = CatchpointState("catchpointCatchupBlockRound")
	// CatchpointStateCatchupBalancesRound is the balance round that is associated with the current running catchpoint catchup. Typically it would be
	// equal to CatchpointStateCatchupBlockRound - 320.
	CatchpointStateCatchupBalancesRound = CatchpointState("catchpointCatchupBalancesRound")
	// CatchpointStateCatchupHashRound is the round that is associated with the hash of the merkle trie. Normally, it's identical to CatchpointStateCatchupBalancesRound,
	// however, it could differ when we catchup from a catchpoint that was created using a different version : in this case,
	// we set it to zero in order to reset the merkle trie. This would force the merkle trie to be re-build on startup ( if needed ).
	CatchpointStateCatchupHashRound = CatchpointState("catchpointCatchupHashRound")
	// CatchpointStateCatchpointLookback is the number of rounds we keep catchpoints for
	CatchpointStateCatchpointLookback = CatchpointState("catchpointLookback")
	// CatchpointStateCatchupVersion is the catchpoint version which the currently catchpoint catchup process is trying to catchup to.
	CatchpointStateCatchupVersion = CatchpointState("catchpointCatchupVersion")
)

// UnfinishedCatchpointRecord represents a stored record of an unfinished catchpoint.
type UnfinishedCatchpointRecord struct {
	Round     basics.Round
	BlockHash crypto.Digest
}

// NormalizedAccountBalance is a staging area for a catchpoint file account information before it's being added to the catchpoint staging tables.
type NormalizedAccountBalance struct {
	// The public key address to which the account belongs.
	Address basics.Address
	// accountData contains the baseAccountData for that account.
	AccountData BaseAccountData
	// resources is a map, where the key is the creatable index, and the value is the resource data.
	Resources map[basics.CreatableIndex]ResourcesData
	// encodedAccountData contains the baseAccountData encoded bytes that are going to be written to the accountbase table.
	EncodedAccountData []byte
	// accountHashes contains a list of all the hashes that would need to be added to the merkle trie for that account.
	// on V6, we could have multiple hashes, since we have separate account/resource hashes.
	AccountHashes [][]byte
	// normalizedBalance contains the normalized balance for the account.
	NormalizedBalance uint64
	// encodedResources provides the encoded form of the resources
	EncodedResources map[basics.CreatableIndex][]byte
	// partial balance indicates that the original account balance was split into multiple parts in catchpoint creation time
	PartialBalance bool
}

// CatchpointFirstStageInfo For the `catchpointfirststageinfo` table.
type CatchpointFirstStageInfo struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Totals           ledgercore.AccountTotals `codec:"accountTotals"`
	TrieBalancesHash crypto.Digest            `codec:"trieBalancesHash"`
	// Total number of accounts in the catchpoint data file. Only set when catchpoint
	// data files are generated.
	TotalAccounts uint64 `codec:"accountsCount"`

	// Total number of accounts in the catchpoint data file. Only set when catchpoint
	// data files are generated.
	TotalKVs uint64 `codec:"kvsCount"`

	// Total number of chunks in the catchpoint data file. Only set when catchpoint
	// data files are generated.
	TotalChunks uint64 `codec:"chunksCount"`
	// BiggestChunkLen is the size in the bytes of the largest chunk, used when re-packing.
	BiggestChunkLen uint64 `codec:"biggestChunk"`

	// StateProofVerificationHash is the hash of the state proof verification data contained in the catchpoint data file.
	StateProofVerificationHash crypto.Digest `codec:"spVerificationHash"`
}

// MakeCatchpointFilePath builds the path of a catchpoint file.
func MakeCatchpointFilePath(round basics.Round) string {
	irnd := int64(round) / 256
	outStr := ""
	for irnd > 0 {
		outStr = filepath.Join(outStr, fmt.Sprintf("%02x", irnd%256))
		irnd = irnd / 256
	}
	outStr = filepath.Join(outStr, strconv.FormatInt(int64(round), 10)+".catchpoint")
	return outStr
}

// RemoveSingleCatchpointFileFromDisk removes a single catchpoint file from the disk. this function does not leave empty directories
func RemoveSingleCatchpointFileFromDisk(dbDirectory, fileToDelete string) (err error) {
	absCatchpointFileName := filepath.Join(dbDirectory, fileToDelete)
	err = os.Remove(absCatchpointFileName)
	if err != nil && !os.IsNotExist(err) {
		// we can't delete the file, abort -
		return fmt.Errorf("unable to delete old catchpoint file '%s' : %v", absCatchpointFileName, err)
	}
	splitedDirName := strings.Split(fileToDelete, string(os.PathSeparator))

	var subDirectoriesToScan []string
	//build a list of all the subdirs
	currentSubDir := ""
	for _, element := range splitedDirName {
		currentSubDir = filepath.Join(currentSubDir, element)
		subDirectoriesToScan = append(subDirectoriesToScan, currentSubDir)
	}

	// iterating over the list of directories. starting from the sub dirs and moving up.
	// skipping the file itself.
	for i := len(subDirectoriesToScan) - 2; i >= 0; i-- {
		absSubdir := filepath.Join(dbDirectory, subDirectoriesToScan[i])
		if _, err := os.Stat(absSubdir); os.IsNotExist(err) {
			continue
		}

		isEmpty, err := isDirEmpty(absSubdir)
		if err != nil {
			return fmt.Errorf("unable to read old catchpoint directory '%s' : %v", subDirectoriesToScan[i], err)
		}
		if isEmpty {
			err = os.Remove(absSubdir)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return fmt.Errorf("unable to delete old catchpoint directory '%s' : %v", subDirectoriesToScan[i], err)
			}
		}
	}

	return nil
}
