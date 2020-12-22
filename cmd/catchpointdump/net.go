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

package main

import (
	"context"
	"fmt"
	"io/ioutil"
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
)

var networkName string
var round int
var relayAddress string

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

func downloadCatchpoint(addr string) ([]byte, error) {
	genesisID := strings.Split(networkName, ".")[0] + "-v1.0"
	url := "http://" + addr + "/v1/" + genesisID + "/ledger/" + strconv.FormatUint(uint64(round), 36)
	fmt.Printf("downloading from %s\n", url)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	timeoutContext, timeoutContextCancel := context.WithTimeout(context.Background(), 40*time.Second)
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
	bytes, err := ioutil.ReadAll(response.Body)
	return bytes, err
}

func saveCatchpointTarFile(addr string, catchpointFileBytes []byte) error {
	// make a directory:
	dirName := "./" + strings.Split(networkName, ".")[0] + "/" + strings.Split(addr, ".")[0]
	os.RemoveAll(dirName)
	err := os.MkdirAll(dirName, 0777)
	if err != nil && !os.IsExist(err) {
		return err
	}
	err = ioutil.WriteFile(dirName+"/"+strconv.FormatUint(uint64(round), 10)+".tar", catchpointFileBytes, 0666)
	return err
}

func makeFileDump(addr string, catchpointFileBytes []byte) error {
	genesisInitState := ledger.InitState{}
	cfg := config.GetDefaultLocal()
	l, err := ledger.OpenLedger(logging.Base(), "./ledger", false, genesisInitState, cfg)
	if err != nil {
		reportErrorf("Unable to open ledger : %v", err)
	}

	defer os.Remove("./ledger.block.sqlite")
	defer os.Remove("./ledger.block.sqlite-shm")
	defer os.Remove("./ledger.block.sqlite-wal")
	defer os.Remove("./ledger.tracker.sqlite")
	defer os.Remove("./ledger.tracker.sqlite-shm")
	defer os.Remove("./ledger.tracker.sqlite-wal")
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
	return nil
}
