// Copyright (C) 2019-2025 Algorand, Inc.
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

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/protocol"
)

var infoFile string

func init() {
	infoCmd.Flags().StringVarP(&infoFile, "tar", "t", "", "Specify the catchpoint file (.tar or .tar.gz) to read")
}

// infoCmd defines a new cobra command that only loads and prints the CatchpointFileHeader.
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show header info from a catchpoint tar file",
	Long:  "Reads the specified catchpoint tar (or tar.gz) file, locates the content.json block, and prints the CatchpointFileHeader fields without loading the entire ledger.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		if infoFile == "" {
			cmd.HelpFunc()(cmd, args)
			return
		}
		fi, err := os.Stat(infoFile)
		if err != nil {
			reportErrorf("Unable to stat file '%s': %v", infoFile, err)
		}
		if fi.Size() == 0 {
			reportErrorf("File '%s' is empty.", infoFile)
		}

		// Open the catchpoint file
		f, err := os.Open(infoFile)
		if err != nil {
			reportErrorf("Unable to open file '%s': %v", infoFile, err)
		}
		defer f.Close()

		// Extract just the file header
		fileHeader, err := loadCatchpointFileHeader(f, fi.Size())
		if err != nil {
			reportErrorf("Error reading CatchpointFileHeader from '%s': %v", infoFile, err)
		}

		// Print out the fields (mimicking the logic in printAccountsDatabase, but simpler)
		if fileHeader.Version == 0 {
			fmt.Printf("No valid header was found.\n")
			return
		}

		fmt.Printf("Version: %d\n", fileHeader.Version)
		fmt.Printf("Balances Round: %d\n", fileHeader.BalancesRound)
		fmt.Printf("Block Round: %d\n", fileHeader.BlocksRound)
		fmt.Printf("Block Header Digest: %s\n", fileHeader.BlockHeaderDigest.String())
		fmt.Printf("Catchpoint: %s\n", fileHeader.Catchpoint)
		fmt.Printf("Total Accounts: %d\n", fileHeader.TotalAccounts)
		fmt.Printf("Total KVs: %d\n", fileHeader.TotalKVs)
		fmt.Printf("Total Online Accounts: %d\n", fileHeader.TotalOnlineAccounts)
		fmt.Printf("Total Online Round Params: %d\n", fileHeader.TotalOnlineRoundParams)
		fmt.Printf("Total Chunks: %d\n", fileHeader.TotalChunks)

		totals := fileHeader.Totals
		fmt.Printf("AccountTotals - Online Money: %d\n", totals.Online.Money.Raw)
		fmt.Printf("AccountTotals - Online RewardUnits: %d\n", totals.Online.RewardUnits)
		fmt.Printf("AccountTotals - Offline Money: %d\n", totals.Offline.Money.Raw)
		fmt.Printf("AccountTotals - Offline RewardUnits: %d\n", totals.Offline.RewardUnits)
		fmt.Printf("AccountTotals - Not Participating Money: %d\n", totals.NotParticipating.Money.Raw)
		fmt.Printf("AccountTotals - Not Participating RewardUnits: %d\n", totals.NotParticipating.RewardUnits)
		fmt.Printf("AccountTotals - Rewards Level: %d\n", totals.RewardsLevel)
	},
}

// loadCatchpointFileHeader reads only enough of the tar (or tar.gz) to
// decode the ledger.CatchpointFileHeader from the "content.json" chunk.
func loadCatchpointFileHeader(catchpointFile io.Reader, catchpointFileSize int64) (ledger.CatchpointFileHeader, error) {
	var fileHeader ledger.CatchpointFileHeader
	fmt.Printf("Scanning for CatchpointFileHeader in tar...\n\n")

	catchpointReader := bufio.NewReader(catchpointFile)
	tarReader, _, err := getCatchpointTarReader(catchpointReader, catchpointFileSize)
	if err != nil {
		return fileHeader, err
	}

	for {
		hdr, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				// We reached the end without finding content.json
				break
			}
			return fileHeader, err
		}

		// We only need the "content.json" file
		if hdr.Name == ledger.CatchpointContentFileName {
			// Read exactly hdr.Size bytes
			buf := make([]byte, hdr.Size)
			_, readErr := io.ReadFull(tarReader, buf)
			if readErr != nil && readErr != io.EOF {
				return fileHeader, readErr
			}

			// Decode into fileHeader
			readErr = protocol.Decode(buf, &fileHeader)
			if readErr != nil {
				return fileHeader, readErr
			}
			// Once we have the fileHeader, we can break out.
			// If you wanted to keep scanning, you could keep going,
			// but it’s not needed just for the header.
			return fileHeader, nil
		}

		// Otherwise skip this chunk
		skipBytes := hdr.Size
		n, err := io.Copy(io.Discard, tarReader)
		if err != nil {
			return fileHeader, err
		}

		// skip any leftover in case we didn't read the entire chunk
		if skipBytes > n {
			// keep discarding until we've skipped skipBytes total
			_, err := io.CopyN(io.Discard, tarReader, skipBytes-n)
			if err != nil {
				return fileHeader, err
			}
		}
	}
	// If we get here, we never found the content.json entry
	return fileHeader, nil
}
