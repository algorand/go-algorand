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
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	tools "github.com/algorand/go-algorand/tools/network"
	"github.com/algorand/go-algorand/util"
)

var networkName string
var round int
var relayAddress string

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
}

var netCmd = &cobra.Command{
	Use:   "net",
	Short: "Download and decode (possibly all) catchpoint files from all or specified the relay(s) on the network for a particular round",
	Long:  "Download and decode (possibly all) catchpoint files from all or specified the relay(s) on the network for a particular round",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		if networkName == "" || round == 0 {
			cmd.HelpFunc()(cmd, args)
			return
		}

		var addrs []string
		var err error
		if relayAddress != "" {
			addrs = []string{relayAddress}
		} else {
			addrs, err = tools.ReadFromSRV("algobootstrap", "tcp", networkName, "", false)
			if err != nil || len(addrs) == 0 {
				reportErrorf("Unable to bootstrap records for '%s' : %v", networkName, err)
			}
		}

		for _, addr := range addrs {
			catchpointFileBytes, err := downloadCatchpoint(addr)
			if err != nil || catchpointFileBytes == nil {
				reportInfof("failed to download catchpoint from '%s' : %v", addr, err)
				continue
			}
			err = saveCatchpointTarFile(addr, catchpointFileBytes)
			if err != nil {
				reportInfof("failed to save catchpoint file for '%s' : %v", addr, err)
				continue
			}
			err = makeFileDump(addr, catchpointFileBytes)
			if err != nil {
				reportInfof("failed to make a dump from tar file for '%s' : %v", addr, err)
				continue
			}
		}
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

func downloadCatchpoint(addr string) ([]byte, error) {
	genesisID := strings.Split(networkName, ".")[0] + "-v1.0"
	url := "http://" + addr + "/v1/" + genesisID + "/ledger/" + strconv.FormatUint(uint64(round), 36)
	fmt.Printf("downloading from %s\n", url)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	timeoutContext, timeoutContextCancel := context.WithTimeout(context.Background(), config.GetDefaultLocal().MaxCatchpointDownloadDuration)
	defer timeoutContextCancel()
	request = request.WithContext(timeoutContext)
	network.SetUserAgentHeader(request.Header)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// check to see that we had no errors.
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound: // server could not find a block with that round numbers.
		return nil, fmt.Errorf("no catchpoint file for round %d", round)
	default:
		return nil, fmt.Errorf("error response status code %d", response.StatusCode)
	}
	wdReader := util.MakeWatchdogStreamReader(response.Body, 4096, 4096, 2*time.Second)
	outBytes := make([]byte, 0, 4096)
	tempBytes := make([]byte, 4096)
	lastProgressUpdate := time.Now()
	progress := -25
	printDownloadProgressLine(progress, 50, url, 0)
	defer printDownloadProgressLine(0, 0, url, 0)
	for {
		n, err := wdReader.Read(tempBytes)
		if err != nil {
			if err == io.EOF {
				outBytes = append(outBytes, tempBytes[:n]...)
				return outBytes, nil
			}
			return nil, err
		}
		if cap(outBytes) < len(outBytes)+n {
			// need to increase buffer.
			newBuffer := make([]byte, cap(outBytes)+n, cap(outBytes)+1024*1024)
			copy(newBuffer, outBytes)
			copy(newBuffer[len(outBytes):], tempBytes[:n])
			outBytes = newBuffer
		} else {
			outBytes = append(outBytes, tempBytes[:n]...)
		}
		err = wdReader.Reset()
		if err != nil {
			if err == io.EOF {
				return outBytes, nil
			}
			return nil, err
		}
		if time.Now().Sub(lastProgressUpdate) > 50*time.Millisecond {
			lastProgressUpdate = time.Now()
			printDownloadProgressLine(progress, 50, url, int64(len(outBytes)))
			progress++
		}
	}
}

func printSaveProgressLine(progress int, barLength int, filename string, dld int64) {
	if barLength == 0 {
		fmt.Printf(escapeCursorUp+escapeDeleteLine+"[ Done ] Saved %s\n", filename)
		return
	}

	outString := "[" + strings.Repeat(escapeSquare, progress) + strings.Repeat(escapeDot, barLength-progress) + "] Saving " + filename + " ..."

	fmt.Printf(escapeCursorUp+escapeDeleteLine+outString+" %s\n", formatSize(dld))
}

func saveCatchpointTarFile(addr string, catchpointFileBytes []byte) (err error) {
	// make a directory:
	dirName := "./" + strings.Split(networkName, ".")[0] + "/" + strings.Split(addr, ".")[0]
	os.RemoveAll(dirName)
	err = os.MkdirAll(dirName, 0777)
	if err != nil && !os.IsExist(err) {
		return
	}
	destFileName := dirName + "/" + strconv.FormatUint(uint64(round), 10) + ".tar"
	file, err2 := os.Create(destFileName) // will create a file with 0666 permission.
	if err2 != nil {
		return err2
	}
	defer func() {
		err = file.Close()
	}()
	writeChunkSize := 64 * 1024
	lastProgressUpdate := time.Now()
	fmt.Printf("\n")
	printSaveProgressLine(0, 50, destFileName, 0)
	progress := uint64(0)
	defer printSaveProgressLine(0, 0, destFileName, 0)
	total := len(catchpointFileBytes)
	for {
		writeSize := writeChunkSize
		if len(catchpointFileBytes) < writeSize {
			writeSize = len(catchpointFileBytes)
		}
		if writeSize <= 0 {
			break
		}
		n, err2 := file.Write(catchpointFileBytes[:writeSize])
		if err2 != nil || n != writeSize {
			return err
		}
		catchpointFileBytes = catchpointFileBytes[n:]
		if time.Now().Sub(lastProgressUpdate) > 50*time.Millisecond && total > 0 {
			lastProgressUpdate = time.Now()
			printSaveProgressLine(int(float64(progress)*50.0/float64(total)), 50, destFileName, int64(progress))

		}
		progress += uint64(n)
	}
	return
}

func makeFileDump(addr string, catchpointFileBytes []byte) error {
	genesisInitState := ledger.InitState{}
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
	var fileHeader ledger.CatchpointFileHeader
	fileHeader, err = loadCatchpointIntoDatabase(context.Background(), catchupAccessor, catchpointFileBytes)
	if err != nil {
		reportErrorf("Unable to load catchpoint file into in-memory database : %v", err)
	}

	dirName := "./" + strings.Split(networkName, ".")[0] + "/" + strings.Split(addr, ".")[0]
	outFile, err := os.OpenFile(dirName+"/"+strconv.FormatUint(uint64(round), 10)+".dump", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	err = printAccountsDatabase("./ledger.tracker.sqlite", fileHeader, outFile)
	if err != nil {
		return err
	}
	outFile.Close()
	return nil
}
