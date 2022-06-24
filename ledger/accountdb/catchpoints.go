// Copyright (C) 2019-2022 Algorand, Inc.
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

package accountdb

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/msgp/msgp"
)

type EncodedBalanceRecordV5 struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Address     basics.Address `codec:"pk,allocbound=crypto.DigestSize"`
	AccountData msgp.Raw       `codec:"ad,allocbound=basics.MaxEncodedAccountDataSize"`
}

type EncodedBalanceRecordV6 struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Address     basics.Address      `codec:"a,allocbound=crypto.DigestSize"`
	AccountData msgp.Raw            `codec:"b,allocbound=basics.MaxEncodedAccountDataSize"`
	Resources   map[uint64]msgp.Raw `codec:"c,allocbound=basics.MaxEncodedAccountDataSize"`
}

// SortUint64 re-export this sort, which is implmented in basics, and being used by the msgp when
// encoding the Resources map below.
type SortUint64 = basics.SortUint64

// AccountHashBuilderV6 calculates the hash key used for the trie by combining the account Address and the account Data
func AccountHashBuilderV6(addr basics.Address, accountData *BaseAccountData, encodedAccountData []byte) []byte {
	hash := make([]byte, 4+crypto.DigestSize)
	hashIntPrefix := accountData.UpdateRound
	if hashIntPrefix == 0 {
		hashIntPrefix = accountData.RewardsBase
	}
	// Write out the lowest 32 bits of the reward base. This should improve the caching of the trie by allowing
	// recent updated to be in-cache, and "older" nodes will be left alone.
	for i, prefix := 3, hashIntPrefix; i >= 0; i, prefix = i-1, prefix>>8 {
		// the following takes the prefix & 255 -> hash[i]
		hash[i] = byte(prefix)
	}
	hash[4] = 0 // set the 5th byte to zero to indicate it's a account base record hash

	prehash := make([]byte, crypto.DigestSize+len(encodedAccountData))
	copy(prehash[:], addr[:])
	copy(prehash[crypto.DigestSize:], encodedAccountData[:])
	entryHash := crypto.Hash(prehash)
	copy(hash[5:], entryHash[1:])
	return hash[:]
}

// ResourcesHashBuilderV6 calculates the hash key used for the trie by combining the account Address and the account Data
func ResourcesHashBuilderV6(addr basics.Address, cidx basics.CreatableIndex, ctype basics.CreatableType, updateRound uint64, encodedResourceData []byte) []byte {
	hash := make([]byte, 4+crypto.DigestSize)
	// Write out the lowest 32 bits of the reward base. This should improve the caching of the trie by allowing
	// recent updated to be in-cache, and "older" nodes will be left alone.
	for i, prefix := 3, updateRound; i >= 0; i, prefix = i-1, prefix>>8 {
		// the following takes the prefix & 255 -> hash[i]
		hash[i] = byte(prefix)
	}
	hash[4] = byte(ctype + 1) // set the 5th byte to one or two ( asset / application ) so we could differentiate the hashes.

	prehash := make([]byte, 8+crypto.DigestSize+len(encodedResourceData))
	copy(prehash[:], addr[:])
	binary.LittleEndian.PutUint64(prehash[crypto.DigestSize:], uint64(cidx))
	copy(prehash[crypto.DigestSize+8:], encodedResourceData[:])
	entryHash := crypto.Hash(prehash)
	copy(hash[5:], entryHash[1:])
	return hash[:]
}

// AccountHashBuilder calculates the hash key used for the trie by combining the account Address and the account Data
func AccountHashBuilder(addr basics.Address, accountData basics.AccountData, encodedAccountData []byte) []byte {
	hash := make([]byte, 4+crypto.DigestSize)
	// Write out the lowest 32 bits of the reward base. This should improve the caching of the trie by allowing
	// recent updated to be in-cache, and "older" nodes will be left alone.
	for i, rewards := 3, accountData.RewardsBase; i >= 0; i, rewards = i-1, rewards>>8 {
		// the following takes the rewards & 255 -> hash[i]
		hash[i] = byte(rewards)
	}
	entryHash := crypto.Hash(append(addr[:], encodedAccountData[:]...))
	copy(hash[4:], entryHash[:])
	return hash[:]
}

// DeleteStoredCatchpoints iterates over the storedcatchpoints table and deletes all the files stored on disk.
// once all the files have been deleted, it would go ahead and remove the entries from the table.
func DeleteStoredCatchpoints(ctx context.Context, e db.Executable, dbDirectory string) (err error) {
	catchpointsFilesChunkSize := 50
	for {
		fileNames, err := GetOldestCatchpointFiles(ctx, e, catchpointsFilesChunkSize, 0)
		if err != nil {
			return err
		}
		if len(fileNames) == 0 {
			break
		}

		for round, fileName := range fileNames {
			err = RemoveSingleCatchpointFileFromDisk(dbDirectory, fileName)
			if err != nil {
				return err
			}
			// clear the entry from the database
			err = StoreCatchpoint(ctx, e, round, "", "", 0)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// RemoveSingleCatchpointFileFromDisk removes a single catchpoint file from the disk. this function does not leave empty directories
func RemoveSingleCatchpointFileFromDisk(dbDirectory, fileToDelete string) (err error) {
	absCatchpointFileName := filepath.Join(dbDirectory, fileToDelete)
	err = os.Remove(absCatchpointFileName)
	if err == nil || os.IsNotExist(err) {
		// it's ok if the file doesn't exist.
		err = nil
	} else {
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
			return fmt.Errorf("unable to Read old catchpoint directory '%s' : %v", subDirectoriesToScan[i], err)
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

const CatchpointDirName = "catchpoints"

func MakeCatchpointDataFilePath(accountsRound basics.Round) string {
	return strconv.FormatInt(int64(accountsRound), 10) + ".Data"
}

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
