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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
)

var argKeepTempfiles, argVerbose, argUnsafeScrypt bool
var argTimeout int
var argVersion string

func main() {
	deadlock.Opts.Disable = true
	rootCmd := &cobra.Command{
		Use:   "client_runner",
		Short: "CLI for running shell scripts under an algorand network",
		Long:  "CLI for running shell scripts under an algorand network",
		Run: func(cmd *cobra.Command, args []string) {
			retCode := run(cmd, args)
			if retCode != 0 {
				os.Exit(retCode)
			}
		},
	}

	rootCmd.Flags().BoolVar(&argKeepTempfiles, "keep-temps", false, "if set, keep all the test files")
	rootCmd.Flags().IntVar(&argTimeout, "timeout", 500, "integer seconds to wait for the scripts to run")
	rootCmd.Flags().BoolVar(&argVerbose, "verbose", false, "")
	rootCmd.Flags().StringVar(&argVersion, "version", "Future", "")
	rootCmd.Flags().BoolVar(&argUnsafeScrypt, "unsafe_scrypt", false, "allows kmd to run with unsafe scrypt attribute. This will speed up tests time")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}

func execute(timeout time.Duration, params ...string) error {
	cmd := exec.Command(params[0], params[1:]...)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		return err
	}
	waitErrorCh := make(chan error, 1)
	go func() {
		waitErrorCh <- cmd.Wait()
	}()
	select {
	case err := <-waitErrorCh:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timeout executing %v", cmd)
	}
}

func run(cmd *cobra.Command, args []string) int {
	tempDir, err := ioutil.TempDir(os.TempDir(), "client_runner_temp")
	if err != nil {
		fmt.Printf("unable to generate temporary directroy\n")
		return 1
	}
	defer func() {
		if !argKeepTempfiles {
			os.RemoveAll(tempDir)
		}
	}()
	currentWorkingDirectory, err := os.Getwd()
	if err != nil {
		fmt.Printf("unable to get current working directory\n")
		return 1
	}
	netdir := filepath.Join(tempDir, "net")
	os.Setenv("NETDIR", netdir)
	os.Setenv("ALGORAND_DATA", filepath.Join(netdir, "Node"))
	os.Setenv("ALGORAND_DATA2", filepath.Join(netdir, "Primary"))

	if argUnsafeScrypt {
		createKMDConfigWithUnsafeScrypt(os.Getenv("ALGORAND_DATA"))
		createKMDConfigWithUnsafeScrypt(os.Getenv("ALGORAND_DATA2"))
	}

	err = execute(60*time.Second, "goal", "network", "create", "-r", netdir, "-n", "tbd", "-t", filepath.Join(currentWorkingDirectory, fmt.Sprintf("../testdata/nettemplates/TwoNodes50Each%s.json", argVersion)))
	if err != nil {
		fmt.Printf("unable to create network - %v\n", err)
		return 1
	}
	err = execute(60*time.Second, "goal", "network", "start", "-r", netdir)
	if err != nil {
		fmt.Printf("unable to start network - %v\n", err)
		return 1
	}

	err = execute(5*time.Second, "goal", "-v")
	if err != nil {
		fmt.Printf("unable to get goal version - %v\n", err)
		return 1
	}

	err = execute(5*time.Second, "goal", "node", "status")
	if err != nil {
		fmt.Printf("unable to get node status - %v\n", err)
		return 1
	}

	runningTests := len(args)
	testsCompleteCh := startAllTests(args)
	if testsCompleteCh == nil {
		return 1
	}
	testFailed := 0
outer:
	for {
		select {
		case testComplete := <-testsCompleteCh:
			if testComplete.successfull {
				fmt.Printf("test %s completed in %v\n", testComplete.testFileName, testComplete.executionTime)
			} else {
				fmt.Printf("test %s failed after %v:\n%s\n", testComplete.testFileName, testComplete.executionTime, testComplete.testOutput)
				testFailed++
			}
			runningTests--
			if runningTests == 0 {
				// we're done!
				break outer
			}
		case <-time.After(time.Duration(argTimeout) * time.Second):
			fmt.Printf("tests timed out after %d seconds.\n", argTimeout)
			break outer
		}
	}

	err = execute(60*time.Second, "goal", "network", "stop", "-r", netdir)
	if err != nil {
		fmt.Printf("unable to stop network - %v\n", err)
		return 1
	}
	if testFailed > 0 {
		return 1
	}
	return 0
}

type testCompleteData struct {
	testFileName  string
	testOutput    string
	executionTime time.Duration
	successfull   bool
}

func startAllTests(tests []string) chan *testCompleteData {
	outChannel := make(chan *testCompleteData, len(tests))
	fmt.Printf("Initialing wallets...\n")
	wallets, err := prepareWallets(len(tests))
	if err != nil {
		fmt.Printf("unable to initialize client runner : %v\n", err)
		return nil
	}
	for i, test := range tests {
		fmt.Printf("starting: %s\n", test)
		go runSingleTest(test, outChannel, wallets[i])
	}
	return outChannel
}

func prepareWallets(walletCount int) (wallets []string, err error) {
	pendingTxn := make([]transactions.Transaction, 0)
	// Make a cache dir for wallet handle tokens
	cacheDir, err := ioutil.TempDir(os.Getenv("ALGORAND_DATA"), "client_runner")
	if err != nil {
		return nil, fmt.Errorf("cannot make temp dir: %v", err)
	}
	// Get libgoal Client
	client, err := libgoal.MakeClient(os.Getenv("ALGORAND_DATA"), cacheDir, libgoal.FullClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create client: %v", err)
	}

	// get default wallet.
	defaultWalletHandle, err := client.GetUnencryptedWalletHandle()
	if err != nil {
		return nil, fmt.Errorf("unable to get default wallet: %v", err)

	}

	defaultWalletAddresses, err := client.ListAddresses(defaultWalletHandle)
	if err != nil {
		return nil, fmt.Errorf("unable to get default wallet addresses: %v", err)
	}

	suggestedParams, err := client.SuggestedParams()
	if err != nil {
		return nil, fmt.Errorf("unable to get suggested params: %v", err)
	}

	for i := 0; i < walletCount; i++ {
		testWalletName := fmt.Sprintf("wallet%d", crypto.RandUint64())
		wallets = append(wallets, testWalletName)
		kmdTestWallet, err := client.CreateWallet([]byte(testWalletName), nil, crypto.MasterDerivationKey{})
		if err != nil {
			return nil, fmt.Errorf("unable to create test wallet: %v", err)
		}
		testWallet, err := client.GetWalletHandleToken(kmdTestWallet, nil)
		if err != nil {
			return nil, fmt.Errorf("unable to init test wallet: %v", err)
		}
		testWalletAddress, err := client.GenerateAddress(testWallet)
		if err != nil {
			return nil, fmt.Errorf("unable to generate test wallet address for wallet %s: %v", testWalletName, err)
		}

		txn, err := client.SendPaymentFromUnencryptedWallet(defaultWalletAddresses[0], testWalletAddress, suggestedParams.MinTxnFee, 1000000000000, nil)
		if err != nil {
			return nil, fmt.Errorf("unable to broadcase transaction: %v", err)
		}
		pendingTxn = append(pendingTxn, txn)

		if i == walletCount-1 {
			statusResponse, err := client.Status()
			maxInitRound := uint64(5)
			for _, txn := range pendingTxn {
				_, err = waitForCommit(client, txn.ID().String(), statusResponse.LastRound+maxInitRound)
				if err != nil {
					return nil, fmt.Errorf("unable to see transaction on chain within timeout: %v", err)
				}
			}
		}
	}
	return
}

func createKMDConfigWithUnsafeScrypt(dir string) {
	cfg, _ := config.LoadKMDConfig(dir)
	cfg.DriverConfig.SQLiteWalletDriverConfig.UnsafeScrypt = true
	cfg.DriverConfig.SQLiteWalletDriverConfig.ScryptParams.ScryptN = 4096
	bytes, _ := json.Marshal(cfg)
	ioutil.WriteFile(filepath.Join(dir, "kmd_config.json"), bytes, 0600)
}

func runSingleTest(test string, outChannel chan *testCompleteData, walletName string) {
	start := time.Now()
	taskCompletionData := &testCompleteData{
		testFileName: test,
	}

	defer func() {
		taskCompletionData.executionTime = time.Now().Sub(start)
		outChannel <- taskCompletionData
	}()

	tempDir, err := ioutil.TempDir(os.TempDir(), "client_runner_temp_"+walletName)
	if err != nil {
		taskCompletionData.testOutput = fmt.Sprintf("unable to create temp directory: %v\n", err)
		return
	}
	removeTempDirectory := true
	defer func() {
		if removeTempDirectory {
			os.RemoveAll(tempDir)
		}
	}()

	timeout := readTestTimeout(test)
	absTestFilename := test
	if !filepath.IsAbs(absTestFilename) {
		currentWorkingDir, _ := os.Getwd()
		absTestFilename = filepath.Join(currentWorkingDir, test)
	}
	cmd := exec.Command(absTestFilename, walletName)
	cmd.Env = append(os.Environ(), "TEMPDIR="+tempDir)
	bufferedOutput := &stringOutputWriter{}
	cmd.Stdout = bufferedOutput
	cmd.Stderr = bufferedOutput
	cmd.Dir = "../.." // The repo's root.
	err = cmd.Start()
	if err != nil {
		taskCompletionData.testOutput = fmt.Sprintf("failed to start test - %v\n%s\n", err, bufferedOutput.Get())
		return
	}
	waitErrorCh := make(chan error, 1)
	go func() {
		waitErrorCh <- cmd.Wait()
	}()
	select {
	case err := <-waitErrorCh:
		if err == nil {
			break
		}
		removeTempDirectory = false
		taskCompletionData.testOutput = fmt.Sprintf("failed to run test %s - %v\n%s\n", test, err, bufferedOutput.Get())
		return
	case <-time.After(timeout):
		taskCompletionData.testOutput = fmt.Sprintf("timed out executing test %s\n", test)
		return
	}
	taskCompletionData.successfull = true
}

func waitForCommit(client libgoal.Client, txid string, transactionLastValidRound uint64) (txn v1.Transaction, err error) {
	// Get current round information
	stat, err := client.Status()
	if err != nil {
		return v1.Transaction{}, err
	}

	for {
		// Check if we know about the transaction yet
		txn, err = client.PendingTransactionInformation(txid)
		if err != nil {
			return v1.Transaction{}, err
		}

		if txn.ConfirmedRound > 0 {
			break
		}

		if txn.PoolError != "" {
			return v1.Transaction{}, err
		}

		// check if we've already committed to the block number equals to the transaction's last valid round.
		// if this is the case, the transaction would not be included in the blockchain, and we can exit right
		// here.
		if transactionLastValidRound > 0 && stat.LastRound >= transactionLastValidRound {
			return v1.Transaction{}, err
		}

		// WaitForRound waits until round "stat.LastRound+1" is committed
		stat, err = client.WaitForRound(stat.LastRound)
		if err != nil {
			return v1.Transaction{}, err
		}
	}

	return
}

func readTestTimeout(filename string) time.Duration {
	fileBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return time.Duration(argTimeout) * time.Second
	}
	bufReader := bufio.NewReader(bytes.NewReader(fileBytes))
	for {
		line, err := bufReader.ReadString('\n')
		if err != nil {
			break
		}
		if !strings.HasPrefix(line, "# TIMEOUT=") {
			continue
		}
		var timeoutSeconds int
		if nProcessed, err := fmt.Sscanf(line, "# TIMEOUT=%d", &timeoutSeconds); nProcessed == 1 && err == nil {
			return time.Duration(timeoutSeconds) * time.Second
		}
	}
	return time.Duration(argTimeout) * time.Second
}

type stringOutputWriter struct {
	deadlock.Mutex
	buf string
}

func (s *stringOutputWriter) Write(p []byte) (n int, err error) {
	s.Lock()
	defer s.Unlock()
	s.buf += string(p)
	return len(p), nil
}
func (s *stringOutputWriter) Get() string {
	s.Lock()
	defer s.Unlock()
	return s.buf
}
