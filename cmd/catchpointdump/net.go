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
	"errors"
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
var loadOnly bool

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
	netCmd.Flags().BoolVarP(&loadOnly, "load", "l", false, "Load only, do not dump")
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
			err = loadAndDump(addr, tarName, genesisInitState)
			if err != nil {
				reportInfof("failed to load/dump from tar file for '%s' : %v", addr, err)
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

func doDownloadCatchpoint(url string, wdReader util.WatchdogStreamReader, out io.Writer) error {
	writeChunkSize := 64 * 1024

	var totalBytes int
	tempBytes := make([]byte, writeChunkSize)
	lastProgressUpdate := time.Now()
	progress := -25
	printDownloadProgressLine(progress, 50, url, 0)

	for {
		n, err := wdReader.Read(tempBytes)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		totalBytes += n
		_, err = out.Write(tempBytes[:n])
		if err != nil {
			return err
		}

		err = wdReader.Reset()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if time.Since(lastProgressUpdate) > 50*time.Millisecond {
			lastProgressUpdate = time.Now()
			printDownloadProgressLine(progress, 50, url, int64(totalBytes))
			progress++
		}
	}
}

// Downloads a catchpoint tar file and returns the path to the tar file.
func downloadCatchpoint(addr string, round int) (string, error) {
	genesisID := strings.Split(networkName, ".")[0] + "-v1.0"
	urlTemplate := "http://" + addr + "/v1/" + genesisID + "/%s/" + strconv.FormatUint(uint64(round), 36)
	catchpointURL := fmt.Sprintf(urlTemplate, "ledger")

	catchpointStream, catchpointCtxCancel, err := getRemoteDataStream(catchpointURL, "catchpoint")
	defer catchpointCtxCancel()
	if err != nil {
		return "", err
	}
	defer catchpointStream.Close()

	dirName := "./" + strings.Split(networkName, ".")[0] + "/" + strings.Split(addr, ".")[0]
	os.RemoveAll(dirName)
	err = os.MkdirAll(dirName, 0777)
	if err != nil && !os.IsExist(err) {
		return "", err
	}
	tarName := dirName + "/" + strconv.FormatUint(uint64(round), 10) + ".tar"
	file, err := os.Create(tarName) // will create a file with 0666 permission.
	if err != nil {
		return "", err
	}
	defer file.Close()

	wdReader := util.MakeWatchdogStreamReader(catchpointStream, 4096, 4096, 5*time.Second)
	defer wdReader.Close()

	err = doDownloadCatchpoint(catchpointURL, wdReader, file)
	if err != nil {
		return "", err
	}

	printDownloadProgressLine(0, 0, catchpointURL, 0)

	err = file.Close()
	if err != nil {
		return "", err
	}

	err = catchpointStream.Close()
	if err != nil {
		return "", err
	}

	return tarName, nil
}

func deleteLedgerFiles(deleteTracker bool) error {
	paths := []string{
		"./ledger.block.sqlite",
		"./ledger.block.sqlite-shm",
		"./ledger.block.sqlite-wal",
	}
	if deleteTracker {
		trackerPaths := []string{
			"./ledger.tracker.sqlite",
			"./ledger.tracker.sqlite-shm",
			"./ledger.tracker.sqlite-wal",
		}
		paths = append(paths, trackerPaths...)
	}

	for _, path := range paths {
		err := os.Remove(path)
		if (err != nil) && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

func loadAndDump(addr string, tarFile string, genesisInitState ledgercore.InitState) error {
	// delete current ledger files.
	deleteLedgerFiles(true)
	cfg := config.GetDefaultLocal()
	l, err := ledger.OpenLedger(logging.Base(), "./ledger", false, genesisInitState, cfg)
	if err != nil {
		reportErrorf("Unable to open ledger : %v", err)
		return err
	}

	defer deleteLedgerFiles(!loadOnly)
	defer l.Close()

	catchupAccessor := ledger.MakeCatchpointCatchupAccessor(l, logging.Base())
	err = catchupAccessor.ResetStagingBalances(context.Background(), true)
	if err != nil {
		reportErrorf("Unable to initialize catchup database : %v", err)
		return err
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
		return err
	}

	if !loadOnly {
		dirName := "./" + strings.Split(networkName, ".")[0] + "/" + strings.Split(addr, ".")[0]
		outFile, err := os.OpenFile(dirName+"/"+strconv.FormatUint(uint64(round), 10)+".dump", os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0755)
		if err != nil {
			return err
		}
		defer outFile.Close()
		err = printAccountsDatabase("./ledger.tracker.sqlite", fileHeader, outFile, excludedFields.GetSlice())
		if err != nil {
			return err
		}
	}
	return nil
}
