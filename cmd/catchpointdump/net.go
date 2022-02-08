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

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	tools "github.com/algorand/go-algorand/tools/network"
	"github.com/algorand/go-algorand/util"
)

var networkName string
var round int
var relayAddress string
var singleCatchpoint bool
var downloadOnly bool

const (
	escapeCursorUp   = string("\033[A") // Cursor Up
	escapeDeleteLine = string("\033[M") // Delete Line
	escapeSquare     = string("▪")
	escapeDot        = string("·")
)

func init() {
	netCmd.Flags().StringVarP(&networkName, "net", "n", "", "Specify the network name ( i.e. mainnet.algorand.network )")
	netCmd.Flags().IntVarP(&round, "round", "r", 0, "Specify the round number ( i.e. 7700000 )")
	netCmd.Flags().StringVarP(&relayAddress, "relay", "p", "", "Relay address to use ( i.e. r-ru.algorand-mainnet.network:4160 )")
	netCmd.Flags().BoolVarP(&singleCatchpoint, "single", "s", true, "Download/process only from a single relay")
	netCmd.Flags().BoolVarP(&downloadOnly, "download", "l", false, "Download only, do not process")
	netCmd.Flags().VarP(excludedFields, "exclude-fields", "e", "List of fields to exclude from the dump: ["+excludedFields.AllowedString()+"]")
}

var netCmd = &cobra.Command{
	Use:          "net",
	Short:        "Download and decode (possibly all) catchpoint files from possibly all or specified the relay(s) on the network for a particular round",
	Long:         "Download and decode (possibly all) catchpoint files from possibly all or specified the relay(s) on the network for a particular round",
	Args:         validateNoPosArgsFn,
	SilenceUsage: true, // prevent printing usage info on error
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		if networkName == "" || round == 0 {
			cmd.HelpFunc()(cmd, args)
			return fmt.Errorf("network or round not set")
		}

		var addrs []string
		if relayAddress != "" {
			addrs = []string{relayAddress}
		} else {
			addrs, err = tools.ReadFromSRV("algobootstrap", "tcp", networkName, "", false)
			if err != nil || len(addrs) == 0 {
				reportErrorf("Unable to bootstrap records for '%s' : %v", networkName, err)
			}
		}

		for _, addr := range addrs {
			var tarName string
			tarName, err = downloadCatchpoint(addr, round)
			if err != nil {
				reportInfof("failed to download catchpoint from '%s' : %v", addr, err)
				continue
			}
			genesisInitState := ledgercore.InitState{
				Block: bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{
					UpgradeState: bookkeeping.UpgradeState{
						CurrentProtocol: protocol.ConsensusCurrentVersion,
					},
				}},
			}
			err = makeFileDump(addr, tarName, genesisInitState)
			if err != nil {
				reportInfof("failed to make a dump from tar file for '%s' : %v", addr, err)
				continue
			}
			// clear possible errors from previous run: at this point we've been succeed
			err = nil
			if singleCatchpoint {
				// a catchpoint processes successfully, exit if needed
				break
			}
		}
		return err
	},
}

func formatSize(dld int64) string {
	if dld < 1024 {
		return fmt.Sprintf("%d bytes", dld)
	} else if dld < 1024*1024 {
		return fmt.Sprintf("%d KB", dld/1024)
	} else if dld < 1024*1024*1024 {
		return fmt.Sprintf("%d MB", dld/(1024*1024))
	} else if dld < 1024*1024*1024*1024 {
		return fmt.Sprintf("%d GB", dld/(1024*1024*1024))
	} else if dld < 1024*1024*1024*1024*1024 {
		return fmt.Sprintf("%d TB", dld/(1024*1024*1024*1024))
	}
	return fmt.Sprintf("%d bytes", dld)
}

func printDownloadProgressLine(progress int, barLength int, url string, dld int64) {
	if barLength == 0 {
		fmt.Printf(escapeCursorUp+escapeDeleteLine+"[ Done ] Downloaded %s\n", url)
		return
	}
	if progress >= barLength {
		progress = progress % barLength
	}
	start, end := progress, progress+barLength/2
	end = end % barLength

	outString := "["
	if start < end {
		for i := 0; i < barLength; i++ {
			if i < start || i > end {
				outString += escapeSquare
			} else {
				outString += escapeDot
			}
		}
	} else {
		for i := 0; i < barLength; i++ {
			if i > start || i < end {
				outString += escapeDot
			} else {
				outString += escapeSquare
			}
		}
	}
	outString += "] Downloading " + url + " ..."
	fmt.Printf(escapeCursorUp+escapeDeleteLine+outString+" %s\n", formatSize(dld))
}

func getRemoteDataStream(url string, hint string) (result io.ReadCloser, ctxCancel context.CancelFunc, err error) {
	fmt.Printf("downloading %s from %s\n", hint, url)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}

	timeoutContext, ctxCancel := context.WithTimeout(context.Background(), config.GetDefaultLocal().MaxCatchpointDownloadDuration)
	request = request.WithContext(timeoutContext)
	network.SetUserAgentHeader(request.Header)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return
	}

	// check to see that we had no errors.
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound: // server could not find a block with that round numbers.
		err = fmt.Errorf("no %s for round %d", hint, round)
		return
	default:
		err = fmt.Errorf("error response status code %d", response.StatusCode)
		return
	}

	result = response.Body
	return
}

func downloadCatchpoint(addr string, round int) (tarName string, err error) {
	genesisID := strings.Split(networkName, ".")[0] + "-v1.0"
	urlTemplate := "http://" + addr + "/v1/" + genesisID + "/%s/" + strconv.FormatUint(uint64(round), 36)
	catchpointURL := fmt.Sprintf(urlTemplate, "ledger")

	catchpointStream, catchpointCtxCancel, err := getRemoteDataStream(catchpointURL, "catchpoint")
	defer catchpointCtxCancel()
	if err != nil {
		return
	}
	defer catchpointStream.Close()

	dirName := "./" + strings.Split(networkName, ".")[0] + "/" + strings.Split(addr, ".")[0]
	os.RemoveAll(dirName)
	err = os.MkdirAll(dirName, 0777)
	if err != nil && !os.IsExist(err) {
		return
	}
	tarName = dirName + "/" + strconv.FormatUint(uint64(round), 10) + ".tar"
	file, err2 := os.Create(tarName) // will create a file with 0666 permission.
	if err2 != nil {
		return tarName, err2
	}
	defer func() {
		err = file.Close()
	}()
	writeChunkSize := 64 * 1024

	wdReader := util.MakeWatchdogStreamReader(catchpointStream, 4096, 4096, 2*time.Second)
	var totalBytes int
	tempBytes := make([]byte, writeChunkSize)
	lastProgressUpdate := time.Now()
	progress := -25
	printDownloadProgressLine(progress, 50, catchpointURL, 0)
	defer printDownloadProgressLine(0, 0, catchpointURL, 0)
	var n int
	for {
		n, err = wdReader.Read(tempBytes)
		if err != nil && err != io.EOF {
			return
		}
		totalBytes += n
		writtenBytes, err2 := file.Write(tempBytes[:n])
		if err2 != nil || n != writtenBytes {
			return tarName, err2
		}

		err = wdReader.Reset()
		if err != nil {
			if err == io.EOF {
				return tarName, nil
			}
			return
		}
		if time.Since(lastProgressUpdate) > 50*time.Millisecond {
			lastProgressUpdate = time.Now()
			printDownloadProgressLine(progress, 50, catchpointURL, int64(totalBytes))
			progress++
		}
	}
}

func makeFileDump(addr string, tarFile string, genesisInitState ledgercore.InitState) error {
	deleteLedgerFiles := func() {
		os.Remove("./ledger.block.sqlite")
		os.Remove("./ledger.block.sqlite-shm")
		os.Remove("./ledger.block.sqlite-wal")
		os.Remove("./ledger.tracker.sqlite")
		os.Remove("./ledger.tracker.sqlite-shm")
		os.Remove("./ledger.tracker.sqlite-wal")
	}
	// delete current ledger files.
	deleteLedgerFiles()
	cfg := config.GetDefaultLocal()
	l, err := ledger.OpenLedger(logging.Base(), "./ledger", false, genesisInitState, cfg)
	if err != nil {
		reportErrorf("Unable to open ledger : %v", err)
	}

	defer deleteLedgerFiles()
	defer l.Close()

	catchupAccessor := ledger.MakeCatchpointCatchupAccessor(l, logging.Base())
	err = catchupAccessor.ResetStagingBalances(context.Background(), true)
	if err != nil {
		reportErrorf("Unable to initialize catchup database : %v", err)
	}

	stats, err := os.Stat(tarFile)
	if err != nil {
		return err
	}
	tarSize := stats.Size()

	reader, err := os.Open(tarFile)
	if err != nil {
		return err
	}
	defer reader.Close()

	var fileHeader ledger.CatchpointFileHeader
	fileHeader, err = loadCatchpointIntoDatabase(context.Background(), catchupAccessor, reader, tarSize)
	if err != nil {
		reportErrorf("Unable to load catchpoint file into in-memory database : %v", err)
	}

	dirName := "./" + strings.Split(networkName, ".")[0] + "/" + strings.Split(addr, ".")[0]
	outFile, err := os.OpenFile(dirName+"/"+strconv.FormatUint(uint64(round), 10)+".dump", os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	err = printAccountsDatabase("./ledger.tracker.sqlite", fileHeader, outFile, excludedFields.GetSlice())
	if err != nil {
		return err
	}
	outFile.Close()
	return nil
}
