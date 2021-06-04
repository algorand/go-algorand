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

package fixtures

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/stretchr/testify/assert"

	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"

	"github.com/algorand/go-algorand/auction"
	auctionClient "github.com/algorand/go-algorand/auction/client"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
)

const (
	defaultAuctionBankPort           string = "0" // 8123
	defaultAuctionConsolePort        string = "0" // 8081
	auctionBankURLPrefix                    = "http://"
	auctionConsoleURLPrefix                 = "http://"
	defaultAuctionMasterStartBalance        = 1000000
	auctionMasterDir                        = "AuctionMaster"
	auctionMinionDir                        = "AuctionMinion"
	auctionBankDir                          = "AuctionBank"
)

// AuctionFixture is a test fixture for testing Auctions
type AuctionFixture struct {
	LibGoalFixture LibGoalFixture
	RestClientFixture
	//algodRestClient          client.RestClient
	auctionBankRestClient    auctionClient.BankRestClient
	auctionConsoleRestClient auctionClient.ConsoleRestClient
	auctionTracker           *auction.Tracker
	context                  context.Context
	contextCancelFunction    context.CancelFunc
	waitGroup                sync.WaitGroup
	finalAuctionID           uint64
	auctionBankPort          uint16
	auctionConsolePort       uint16
	auctionBankRestURL       string
	auctionConsoleRestURL    string
	abPid                    string
	abPort                   string
	acPid                    string
	acPort                   string
	bidderSecretKeyCache     map[string]crypto.PrivateKey
}

// AuctionMinionState is the structure of the data stored in the auctionminion.state file
type AuctionMinionState struct {
	AuctionKey string
	AuctionID  uint64
	StartRound uint64
	AlgodURL   string
	AlgodToken string
}

// AuctionBankKey holds the auction bank's string key
type AuctionBankKey struct {
	BankKey string
}

// PaymentTransactionArray holds an array of signed txns
type PaymentTransactionArray struct {
	paymentTransaction []transactions.SignedTxn
}

// InitParams is a reduced version of what appears in auctionmaster's initparams.json
type InitParams struct {
	AuctionID  uint64
	FirstRound uint64
}

// GetLibGoalClient gets a libgoal client pointing at the primary node
func (f *AuctionFixture) GetLibGoalClient() libgoal.Client {
	nodeController, err := f.GetNodeController("Primary")
	if err != nil {
		f.t.Fatalf("Error calling GetLibGoalClient() with error %v", err)
	}
	return f.LibGoalFixture.GetLibGoalClientFromNodeControllerNoKeys(nodeController)
}

// GetAlgodRestClient gets a rest client pointing at the primary node
func (f *AuctionFixture) GetAlgodRestClient() client.RestClient {
	nodeController, err := f.GetNodeController("Primary")
	if err != nil {
		f.t.Fatalf("Error calling GetNodeController() with error %v", err)
	}
	return f.GetAlgodClientForController(nodeController)
}

// AuctionBankRestClient returns a Auction Bank Rest Client
func (f *AuctionFixture) AuctionBankRestClient(restURL *url.URL) auctionClient.BankRestClient {
	return auctionClient.MakeAuctionBankRestClient(*restURL)
}

// AuctionConsoleRestClient returns a Auction Console Rest Client
func (f *AuctionFixture) AuctionConsoleRestClient(restURL *url.URL) auctionClient.ConsoleRestClient {
	return auctionClient.MakeAuctionConsoleRestClient(*restURL)
}

// GetAuctionBankRestClient gets the auction bank rest client
func (f *AuctionFixture) GetAuctionBankRestClient() auctionClient.BankRestClient {
	if (auctionClient.BankRestClient{}) == f.auctionBankRestClient {
		auctionBankURL, err := url.Parse(f.auctionBankRestURL)
		if err != nil {
			f.t.Errorf("Error parsing auction bank url %s, err: %s", f.auctionBankRestURL, err)
			return f.auctionBankRestClient
		}
		f.auctionBankRestClient = f.AuctionBankRestClient(auctionBankURL)
	}
	return f.auctionBankRestClient
}

// GetAuctionConsoleRestClient returns the auction console rest client
func (f *AuctionFixture) GetAuctionConsoleRestClient() auctionClient.ConsoleRestClient {
	if (auctionClient.ConsoleRestClient{}) == f.auctionConsoleRestClient {
		auctionConsoleURL, err := url.Parse(f.auctionConsoleRestURL)
		if err != nil {
			f.t.Errorf("Error parsing auction console url %s, err: %s", f.auctionConsoleRestURL, err)
			return f.auctionConsoleRestClient
		}
		f.auctionConsoleRestClient = f.AuctionConsoleRestClient(auctionConsoleURL)
	}
	return f.auctionConsoleRestClient
}

// Setup is called to initialize the test fixture for the test(s), uses default ports for auction bank and console
func (f *AuctionFixture) Setup(t TestingTB, templateFile string) (err error) {

	f.t = SynchronizedTest(t)

	f.bidderSecretKeyCache = make(map[string]crypto.PrivateKey)

	// call setup on parent RestClientFixture
	f.RestClientFixture.Setup(t, templateFile)

	// setup context for auction fixture
	f.context, f.contextCancelFunction = context.WithCancel(context.Background())

	return
}

// Shutdown implements the Fixture.Shutdown method
func (f *AuctionFixture) Shutdown() (err error) {

	// call context cancel
	f.contextCancelFunction()

	// wait for cancellation to finish
	f.waitGroup.Wait()

	// terminate auction bank
	auctionBankPidFile := filepath.Join(f.rootDir, "AuctionBank", "auctionbank.pid")

	err = f.Stop(auctionBankPidFile)
	if err != nil {
		f.t.Errorf("Unable to shutdown auction bank process %s", err)
	}

	auctionConsolePidFile := filepath.Join(f.rootDir, "AuctionConsole", "auctionconsole.pid")
	err = f.Stop(auctionConsolePidFile)

	if err != nil {
		f.t.Errorf("Unable to shutdown auction console process %s", err)
	}

	f.RestClientFixture.Shutdown()

	return
}

// Stop determines the node's PID from its PID file and uses that to kill it.
func (f *AuctionFixture) Stop(pidFile string) error {
	pid, err := f.GetPID(pidFile)
	if err != nil {
		f.t.Errorf("Unable to locate PID file: %s", pidFile)
		return err
	}

	process, err := os.FindProcess(int(pid))
	if process == nil || err != nil {
		f.t.Errorf("Unable to locate PID: %d", pid)
		return err
	}

	err = util.KillProcess(int(pid), syscall.SIGTERM)
	if err != nil {
		f.t.Errorf("Unable to kill PID: %d", pid)
		return err
	}
	waitLong := time.After(time.Second * 30)
	for {
		// Send null signal - if process still exists, it'll return nil
		// So when we get an error, assume it's gone.
		if err = process.Signal(syscall.Signal(0)); err != nil {
			return nil
		}
		select {
		case <-waitLong:
			return util.KillProcess(int(pid), syscall.SIGKILL)
		case <-time.After(time.Millisecond * 100):
		}
	}
}

// GetPID returns the PID from the algod.pid file in the node's data directory, or an error
func (f *AuctionFixture) GetPID(pidFile string) (pid uint64, err error) {
	pidStr, err := ioutil.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	pid, err = strconv.ParseUint(strings.TrimSuffix(string(pidStr), "\n"), 10, 32)
	return
}

// StartAuction starts auction with default auction master balance
func (f *AuctionFixture) StartAuction(auctionParamFile string) (inputParams InitParams, consoleViewParams auction.Params, stdout string, errorOutput string, err error) {
	return f.StartAuctionWithAuctionMasterBalance(auctionParamFile, defaultAuctionMasterStartBalance)
}

// StartAuctionWithAuctionMasterBalance starts the auction with a given master balance
func (f *AuctionFixture) StartAuctionWithAuctionMasterBalance(auctionParamFile string, auctionMasterStartBalance uint64) (inputParams InitParams, consoleViewParams auction.Params, stdout string, errorOutput string, err error) {

	auctionParamFilePath := filepath.Join(f.testDataDir, auctionParamFile)

	auctionBankPortString := fmt.Sprintf(":%s", defaultAuctionBankPort)
	auctionConsolePortString := fmt.Sprintf(":%s", defaultAuctionConsolePort)

	startScript := filepath.Join("../../../scripts", "auctionStart.sh")

	cmd := exec.Command(startScript, f.rootDir, auctionBankPortString, auctionConsolePortString, auctionParamFilePath, fmt.Sprintf("%d", auctionMasterStartBalance))

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err = cmd.Run()
	stdout = outb.String()
	errorOutput = errb.String()

	if err != nil {
		f.t.Errorf("error processing script err: %+v", err)
		f.t.Errorf("error processing script stdout: %s", stdout)
		f.t.Errorf("error processing script stderr: %s", errorOutput)
		return
	}

	fmt.Println(stdout)

	f.abPid, err = f.GetAuctionBankPid()
	f.abPort, _ = f.GetAuctionBankPort()

	f.acPid, _ = f.GetAuctionConsolePid()
	f.acPort, _ = f.GetAuctionConsolePort()

	f.auctionBankRestURL = fmt.Sprintf("%s%s", auctionBankURLPrefix, f.abPort)
	f.auctionConsoleRestURL = fmt.Sprintf("%s%s", auctionConsoleURLPrefix, f.acPort)

	inputParams, err = f.GetActualAuctionParams()
	if err != nil {
		f.t.Errorf("error getting actual auction params: %v", err)
		return
	}

	// store the final auction id.  we used to support a series of
	// auctions, but that is no longer the case, so the final auction ID
	// is the first one.
	f.finalAuctionID = inputParams.AuctionID

	var resultParamsResponse auctionClient.ParamsResponse
	for {
		resultParamsResponse, err = f.GetAuctionConsoleRestClient().Params(inputParams.AuctionID)
		if err != nil {
			f.t.Errorf("Error calling console.Params(auctionID=%d) with error: %v", inputParams.AuctionID, err)
			return
		}
		if resultParamsResponse != (auctionClient.ParamsResponse{}) {
			break
		}
		time.Sleep(1000000)
	}

	consoleViewParams = resultParamsResponse.Params

	return
}

// EndAuction ends the current auction by invoking the auctionEnd script
func (f *AuctionFixture) EndAuction() (stdout string, errorOutput string, err error) {

	endScript := filepath.Join("../../../scripts", "auctionEnd.sh")

	cmd := exec.Command(endScript, f.rootDir, f.abPort, f.acPort, fmt.Sprintf("%d", f.finalAuctionID))

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err = cmd.Run()
	stdout = outb.String()
	errorOutput = errb.String()
	if err != nil {
		f.t.Errorf("error processing auction end script %s", err)
		f.t.Logf("out: %s\nerr: %s", stdout, errorOutput)
		return
	}

	ra, err := f.GetRunningAuction()
	if ra != nil {
		ra.Settle(false)
	}

	return
}

// CancelAuction cancels the current auction by invoking the auctionCancel script
func (f *AuctionFixture) CancelAuction() (stdout string, errorOutput string, err error) {

	endScript := filepath.Join("../../../scripts", "auctionCancel.sh")

	cmd := exec.Command(endScript, f.rootDir, f.abPort, f.acPort, fmt.Sprintf("%d", f.finalAuctionID))

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err = cmd.Run()
	stdout = outb.String()
	errorOutput = errb.String()
	if err != nil {
		f.t.Errorf("error processing auction cancel script %s", err)
		f.t.Logf("out: %s\nerr: %s", stdout, errorOutput)
		return
	}

	ra, err := f.GetRunningAuction()
	if ra != nil {
		ra.Settle(true)
	}

	return
}

// GetRunningAuction returns the running auction object, delegates to auction tracker
func (f *AuctionFixture) GetRunningAuction() (runningAuction *auction.RunningAuction, err error) {

	at, err := f.GetAuctionTracker() //, round)
	if err != nil {
		f.t.Errorf("error on call to GetAuctionTracker() %+v", err)
		return
	}
	lastAuctionID, err := at.LastAuctionID()
	if err != nil {
		f.t.Logf("warning, at.LastAuctionID() resulted in error: %+v", err)
		return
	}

	runningAuction = at.Auctions[lastAuctionID].RunningAuction
	return
}

// GetAuctionTracker creates and returns a singleton auction tracker instance for access to the auction status and runningAuction object
func (f *AuctionFixture) GetAuctionTracker() (auctionTracker *auction.Tracker, err error) {

	if f.auctionTracker != nil {
		return f.auctionTracker, err
	}

	ams, err := f.GetAuctionMinionInitialState()
	auctionKey := ams.AuctionKey

	at, err := auction.MakeTracker(ams.StartRound, auctionKey)

	if err != nil {
		f.t.Errorf("error calling MakeTracker( round = %d, auctionKey = %s)", ams.StartRound, auctionKey)
		return
	}

	f.waitGroup.Add(1)

	go at.LiveUpdateWithContext(f.context, &f.waitGroup, f.GetAlgodRestClient())

	f.auctionTracker = at

	return at, err
}

// GetAuctionMasterPublicKey returns the auction master public key from the file auctionMaster/master.pub
func (f *AuctionFixture) GetAuctionMasterPublicKey() (auctionKey string, err error) {
	auctionMasterPubKeyFile := filepath.Join(f.rootDir, auctionMasterDir, "master.pub")
	dat, err := ioutil.ReadFile(auctionMasterPubKeyFile)
	if err != nil {
		logging.Base().Error(err)
		return
	}
	auctionKey = strings.TrimSpace(string(dat))
	return
}

// GetAuctionMinionInitialState reads in the auction minion state from the auction minion state file
func (f *AuctionFixture) GetAuctionMinionInitialState() (ams AuctionMinionState, err error) {

	auctionMinionStateFile := filepath.Join(f.rootDir, auctionMinionDir, "auctionminion.state")
	dat, err := ioutil.ReadFile(auctionMinionStateFile)
	if err != nil {
		logging.Base().Error(err)
		return
	}

	err = json.Unmarshal(dat, &ams)
	if err != nil {
		logging.Base().Error(err)
		return
	}
	return
}

// GetActualAuctionParams reads in the actual auction params ${AUCTIONMASTERTESTDIR}/initparams.json
func (f *AuctionFixture) GetActualAuctionParams() (aip InitParams, err error) {

	auctionInitialParamsFile := filepath.Join(f.rootDir, auctionMasterDir, "initparams.json")
	dat, err := ioutil.ReadFile(auctionInitialParamsFile)
	if err != nil {
		logging.Base().Error(err)
		return
	}

	err = json.Unmarshal(dat, &aip)
	if err != nil {
		f.t.Logf("unmarshalling auction params: %+v ", err)
		return
	}

	return
}

// GetAuctionBankKey reads the bank keyfile
func (f *AuctionFixture) GetAuctionBankKey() (abk string, err error) {

	auctionBankKeyFile := filepath.Join(f.rootDir, auctionBankDir, "bank.key")
	dat, err := ioutil.ReadFile(auctionBankKeyFile)
	if err != nil {
		logging.Base().Error(err)
		return
	}
	auctionBankKeyString := string(dat)
	s := strings.Split(auctionBankKeyString, ":")

	abk = strings.TrimSpace(s[1])

	return
}

// GetAuctionStartBroadcastMessage will read in the auction master start transaction
func (f *AuctionFixture) GetAuctionStartBroadcastMessage() (abs string, err error) {

	auctionStartBroadcastFile := filepath.Join(f.rootDir, "AuctionMaster", "auction1.starttx")
	dat, err := ioutil.ReadFile(auctionStartBroadcastFile)
	if err != nil {
		logging.Base().Error(err)
		return
	}
	abs = string(dat)

	return
}

// GetLastSettledID will get the last settled id
func (f *AuctionFixture) GetLastSettledID() (lastSettledID string, err error) {

	lastSettledIDFile := filepath.Join(f.rootDir, "AuctionMaster", "lastsettled")
	dat, err := ioutil.ReadFile(lastSettledIDFile)
	if err != nil {
		f.t.Errorf("Error reading file %s,  %+v", lastSettledIDFile, err)
		return
	}
	lastSettledID = strings.TrimSpace(string(dat))

	return
}

// readAndDecode reads data from [filename] using readFile, and
// decodes it into [obj].
func (f *AuctionFixture) readFile(filePath string) (data []byte, err error) {
	data, err = ioutil.ReadFile(filePath)
	if err != nil {
		f.t.Errorf("Reading %s: %v", filePath, err)
		return
	}

	if len(data) == 0 {
		logging.Base().Warnf("Reading empty file %s: %v", filePath, err)
		return
	}

	return
}

// readAndDecode reads data from [filename] using readFile, and
// decodes it into [obj].
func (f *AuctionFixture) readAndDecode(filePath string, obj interface{}) {
	data, err := f.readFile(filePath)
	if err != nil {
		f.t.Errorf("Reading %s: %v", filePath, err)
		return
	}

	err = protocol.DecodeReflect(data, obj)
	if err != nil {
		f.t.Errorf("Decoding from %s: %v", filePath, err)
		return
	}

	return
}

// GetSettlementTransactionBytesFromFile will retrieve the Settlement Transaction from the auction#.settletx file for the given auction id
func (f *AuctionFixture) GetSettlementTransactionBytesFromFile(trxID uint64) (settleTxnBytes []byte, err error) {

	settlementTransactionFileName := fmt.Sprintf("auction%d.settletx", trxID)
	settlementTransactionFile := filepath.Join(f.rootDir, "AuctionMaster", settlementTransactionFileName)

	settleTxnBytes, err = f.readFile(settlementTransactionFile)
	if err != nil {
		f.t.Errorf("Error reading settlement transaction file %v", err)
	}

	return
}

// GetSettlementTransactionStructureFromFile will retrieve the Settlement Transaction from the auction#.settletx file for the given auction id
func (f *AuctionFixture) GetSettlementTransactionStructureFromFile(trxID string) (st transactions.SignedTxn, err error) {

	settlementTransactionFileName := fmt.Sprintf("auction%s.settletx", trxID)
	settlementTransactionFile := filepath.Join(f.rootDir, "AuctionMaster", settlementTransactionFileName)

	f.readAndDecode(settlementTransactionFile, &st)

	return
}

// GetPaymentTransactionBytesFromFile will return the payment transaction blob for the given auction id
func (f *AuctionFixture) GetPaymentTransactionBytesFromFile(auctionID uint64) (paymentTransactionsBytes []byte, err error) {

	paymentTransactionFileName := fmt.Sprintf("auction%d.paymenttx", auctionID)
	paymentTransactionFile := filepath.Join(f.rootDir, "AuctionMaster", paymentTransactionFileName)

	paymentTransactionsBytes, err = f.readFile(paymentTransactionFile)
	if err != nil {
		f.t.Errorf("Error reading settlement payment transactions from file %v", err)
	}

	return
}

// GetPaymentTransactionStructureFromFile will return the payment transaction blob for the given auction id
func (f *AuctionFixture) GetPaymentTransactionStructureFromFile(auctionID string) (paymentTransactions []transactions.SignedTxn, err error) {

	paymentTransactionFileName := fmt.Sprintf("auction%s.paymenttx", auctionID)
	paymentTransactionFile := filepath.Join(f.rootDir, "AuctionMaster", paymentTransactionFileName)

	f.readAndDecode(paymentTransactionFile, &paymentTransactions)

	return
}

// GetStartTransactionFile gets the start transaction file for given auction id
func (f *AuctionFixture) GetStartTransactionFile(auctionID string) (startTransaction string, err error) {

	f.t.Logf("GetStartTransactionFile( %s )", auctionID, startTransaction)

	startTransactionFileName := fmt.Sprintf("auction%s.starttx", auctionID)
	startTransactionFile := filepath.Join(f.rootDir, "AuctionMaster", startTransactionFileName)
	dat, err := ioutil.ReadFile(startTransactionFile)
	if err != nil {
		logging.Base().Error(err)
		return
	}
	startTransaction = string(dat)

	return
}

// GetCurrentPriceFromConsole queries the auctionconsole current price
func (f *AuctionFixture) GetCurrentPriceFromConsole(auction1 auction.RunningAuction) (price uint64, err error) {

	currentPrice, err := f.auctionConsoleRestClient.CurrentPrice(auction1.Params.AuctionID, auction1.Params.DepositRound)
	if err != nil {
		logging.Base().Error("Error retrieving current price for auction %d from auction console: %s", auction1.Params.AuctionID, err)
		return
	}

	price = currentPrice.Price
	return
}

// SettleAuctionBank is a utility function to invoke SettleAuction on AuctionBank to finalize the processing of auctions
func (f *AuctionFixture) SettleAuctionBank(auctionKey string, auctionID uint64) (err error) {
	var settleAuctionQuery auctionClient.SettleAuctionQuery
	settleAuctionQuery.AuctionKey = string(auctionKey)

	settleAuctionQuery.OutcomesBlob, err = f.GetPaymentTransactionBytesFromFile(auctionID)
	settleAuctionQuery.SigSettlementBlob, err = f.GetSettlementTransactionBytesFromFile(auctionID)

	err = f.GetAuctionBankRestClient().SettleAuction(settleAuctionQuery)
	if err != nil {
		logging.Base().Error("Error calling SettleAuction(%+v): %v", settleAuctionQuery, err)
		return
	}
	return
}

// ComputeCurrentPrice is a utility function that mimic's the auction console's price calculation
func (f *AuctionFixture) ComputeCurrentPrice(curRound, initialRound, numChunks, priceChunkRounds, lastPrice, maxPriceMultiple uint64) (price uint64, err error) {

	// the below logic, comments included, mimics price computation from auctionconsole:
	if curRound < initialRound {
		err = fmt.Errorf("current round %d is before initial round %d", curRound, initialRound)
		return
	}
	lastRound := initialRound + numChunks*priceChunkRounds
	if curRound > lastRound {
		err = fmt.Errorf("current round %d is after final round %d", curRound, lastRound)
		return
	}

	// Compute the chunk in which [rnd] falls for this auction.
	chunkNum := (curRound - initialRound) / priceChunkRounds

	// How many chunk price increase steps are we away from the
	// LastPrice (reserve)?
	chunksToEnd := numChunks - chunkNum - 1

	// We want to compute the price increase over LastPrice for this
	// chunk.  The total increase from LastPrice to the first chunk
	// is:
	//
	//   x := LastPrice * (MaxPriceMultiple-1)
	//
	// With arbitrary-precision real numbers, each chunk step would
	// thus increase the price by:
	//
	//   y := x / (ra.Params.NumChunks-1)
	//
	// because there are NumChunks-1 steps between NumChunks chunks.
	// And finally, the increase for our case would be
	//
	//   z := y * chunksToEnd
	//
	// To minimize rounding error, we do all of the multiplication
	// first, followed by the division, and we overflow-check the
	// multiplication just in case (mostly to guard against auction
	// configuration errors).

	// Main
	x := lastPrice * (maxPriceMultiple - 1)

	w, overflowed := basics.OMul(x, chunksToEnd)
	if overflowed {
		err = fmt.Errorf("overflow while computing chunk increase")
		return
	}

	// Guard against an auction with a single chunk: avoiding divide-by-zero.
	var z uint64
	if w == 0 {
		z = 0
	} else {
		z = w / (numChunks - 1)
	}

	price = lastPrice + z

	// end logic duplicated from auctionconsole main

	return
}

// MakeBankAccountIfNoneExists checks if a given username is registered with the auctionbank, and makes the account if not registered
func (f *AuctionFixture) MakeBankAccountIfNoneExists(username string) (err error) {

	statusQuery := auctionClient.StatusQuery{Username: username}
	statusResponse, err := f.GetAuctionBankRestClient().AccountStatus(statusQuery)
	if err != nil {
		f.t.Errorf("Error getting Account Status: %+v", err)
		return err
	}

	// if the user doesn't exist yet, it will report balance and pending 0
	// additionally, creating a user sets balance and pending to zero if the user already exists
	// so only call CreateUser if doing so will not overwrite a balance-having or pending-having user
	if statusResponse.Balance == 0 && statusResponse.Pending == 0 {
		creationQuery := auctionClient.CreateUserQuery{Username: username}
		err = f.auctionBankRestClient.CreateUser(creationQuery)
		if err != nil {
			f.t.Errorf("creating Auction bank user failed: %+v", err)
		}
	}

	return err
}

// MakeSignedDeposit constructs a signed deposit using the auction bank
func (f *AuctionFixture) MakeSignedDeposit(usernameWithBank, auctionKey, bidderKey string, auctionID, amountDeposited uint64) (signedDepositNote client.BytesBase64, err error) {

	transferInQuery := auctionClient.TransferInQuery{Username: usernameWithBank, Amount: amountDeposited + 10}
	err = f.GetAuctionBankRestClient().TransferIn(transferInQuery)
	if err != nil {
		f.t.Errorf("Transfer %+v failed with err %v", transferInQuery, err)
		return
	}

	deposit := auctionClient.DepositAuctionQuery{
		Username:  usernameWithBank,
		Auction:   auctionKey,
		Bidder:    bidderKey,
		AuctionID: auctionID,
		Amount:    amountDeposited,
	}

	depositStatus, err := f.GetAuctionBankRestClient().DepositAuction(deposit)

	if err != nil {
		f.t.Errorf("DepositAuction %+v failed with err %v", deposit, err)
		return
	}

	if !depositStatus.Success {
		err = fmt.Errorf("no error received from auctionbank in MakeSignedDeposit but depositStatus.Success was false, deposit query: %+v", deposit)
		f.t.Error(err)
		return
	}

	signedDepositNote = depositStatus.SignedDepositNote

	return
}

// GetDefaultWalletAndPassword is a convenience function to return the default wallet and password
func (f *AuctionFixture) GetDefaultWalletAndPassword() (walletHandel []byte, password string, err error) {
	libGoalClient := f.GetLibGoalClient()
	walletHandel, err = libGoalClient.GetUnencryptedWalletHandle()
	password = ""
	return
}

// MakeSignedBid calls MakeSignedBidWithWallet against the default wallet
func (f *AuctionFixture) MakeSignedBid(bidID uint64, auctionKey string, auctionID uint64, account string, maxPrice uint64, bidCurrency uint64) (signedBidNote []byte, err error) {
	wh, password, err := f.GetDefaultWalletAndPassword()
	return f.MakeSignedBidWithWallet(wh, password, bidID, auctionKey, auctionID, account, maxPrice, bidCurrency)
}

// MakeSignedBidWithWallet constructs a bid and signs it
func (f *AuctionFixture) MakeSignedBidWithWallet(walletHandle []byte, password string, bidID uint64, auctionKey string, auctionID uint64, account string, maxPrice uint64, bidCurrency uint64) (signedBidNote []byte, err error) {

	signedBidNote, err = f.signBid(walletHandle, password, account, bidCurrency, maxPrice, bidID, auctionKey, auctionID)
	if err != nil {
		f.t.Errorf("SignBid(account=%s, bidCurrency=%d, maxPrice=%d, bidID=%d, auctionKey=%s, auctionID=%d) failed with err %v", account, bidCurrency, maxPrice, bidID, auctionKey, auctionID, err)
		return
	}
	return
}

// placeholder signBid method until exposed by Wallet or Auction
func (f *AuctionFixture) signBid(walletHandle []byte, password string, account string, bidCurrency uint64, maxPrice uint64, bidID uint64, auctionKey string, auctionID uint64) (signedBidNote []byte, err error) {

	libGoalClient := f.GetLibGoalClient()

	accountAddress, err := basics.UnmarshalChecksumAddress(account)
	if err != nil {
		f.t.Errorf("Errror getting account address %v", err)
	}

	// get secret key for the bidder, check cache first
	secretKey, foundSecretKey := f.bidderSecretKeyCache[account]
	if !foundSecretKey {
		var exportKeyResponse kmdapi.APIV1POSTKeyExportResponse
		exportKeyResponse, err = libGoalClient.ExportKey(walletHandle, password, account)
		if err != nil {
			f.t.Errorf("ExportKey(walletHandleBytes = %s , passwordBytes = %s, accountBytes = %s ) failed with err %v", walletHandle, []byte(password), accountAddress, err)
			return
		}
		secretKey = exportKeyResponse.PrivateKey
		f.bidderSecretKeyCache[account] = secretKey
	}

	auctionKeyAddress, err := basics.UnmarshalChecksumAddress(auctionKey)
	if err != nil {
		f.t.Errorf("Error getting auctionKey address %v", err)
	}

	var auctionKeyCryptoDigest crypto.Digest
	copy(auctionKeyCryptoDigest[:], auctionKeyAddress[:])

	var accountCryptoDigest crypto.Digest
	copy(accountCryptoDigest[:], accountAddress[:])

	bid := auction.Bid{
		BidderKey:   accountCryptoDigest,
		BidCurrency: bidCurrency,
		MaxPrice:    maxPrice,
		BidID:       bidID,
		AuctionKey:  auctionKeyCryptoDigest,
		AuctionID:   auctionID,
	}

	sig, err := f.signRaw(secretKey, bid)
	if err != nil {
		f.t.Errorf("signRaw failed with err %v", err)
		return
	}

	signedBidNote = client.BytesBase64(protocol.Encode(&auction.NoteField{
		Type: auction.NoteBid,
		SignedBid: auction.SignedBid{
			Bid: bid,
			Sig: sig,
		},
	}))

	return
}

func (f *AuctionFixture) signRaw(secretKey crypto.PrivateKey, msg crypto.Hashable) (sig crypto.Signature, err error) {

	secrets, err := crypto.SecretKeyToSignatureSecrets(secretKey)
	if err != nil {
		return
	}
	sig = secrets.Sign(msg)

	return
}

// MakeAndPostBidAndDeposit uses the default wallet to MakeAndPostBidAndDepositWithWallet
func (f *AuctionFixture) MakeAndPostBidAndDeposit(bidID, auctionID uint64, auctionKey, biddingAccount string, maxPricePerAlgo, currencySpentOnBid uint64) (txid string, transactionID string, err error) {
	libGoalClient := f.GetLibGoalClient()

	wh, _ := libGoalClient.GetUnencryptedWalletHandle()
	password := ""

	return f.MakeAndPostBidAndDepositWithWallet(wh, password, bidID, auctionID, auctionKey, biddingAccount, maxPricePerAlgo, currencySpentOnBid)
}

// MakeAndPostBidAndDepositWithWallet does everything from the "create a bank account if necessary" step to the "post the bid and deposit to blockchain" step
func (f *AuctionFixture) MakeAndPostBidAndDepositWithWallet(walletHandle []byte, password string, bidID, auctionID uint64, auctionKey, biddingAccount string, maxPricePerAlgo, currencySpentOnBid uint64) (txid string, transactionID string, err error) {

	if auctionID == 0 {
		f.t.Fatalf("auction id is 0")
	}

	err = f.MakeBankAccountIfNoneExists(biddingAccount)

	if err != nil {
		f.t.Errorf("MakeBankAccountIfNoneExists %+v failed with err %v", biddingAccount, err)
		return
	}

	depositBlob, err := f.MakeSignedDeposit(biddingAccount, auctionKey, biddingAccount, auctionID, currencySpentOnBid)

	if err != nil {
		f.t.Errorf("MakeSignedDeposit (usernameWithBank=%s, auctionKey=%s, biddingAccount=%s, auctionID=%d, currencySpentOnBid=%d )failed with err %v", biddingAccount, auctionKey, biddingAccount, auctionID, currencySpentOnBid, err)
		return
	}

	bidBlob, err := f.MakeSignedBidWithWallet(walletHandle, password, bidID, auctionKey, auctionID, biddingAccount, maxPricePerAlgo, currencySpentOnBid)

	if err != nil {
		f.t.Errorf("MakeSignedBid (bidID=%s, auctionKey=%s, auctionID=%d, biddingAccount=%s, maxPricePerAlgo=%d, currencySpentOnBid=%d )failed with err %v", bidID, auctionKey, auctionID, biddingAccount, maxPricePerAlgo, currencySpentOnBid, err)
		return
	}

	unitedBlob := append(depositBlob, bidBlob...)

	amountToPay := uint64(0)

	transactionFee := uint64(1)

	libGoalClient := f.GetLibGoalClient()

	tx, err := libGoalClient.SendPaymentFromUnencryptedWallet(biddingAccount, auctionKey, transactionFee, amountToPay, unitedBlob)
	txid = tx.ID().String()

	if err != nil {
		f.t.Errorf("SendPayment( fromAccount=%s, toAccount=%s, transactionFee=%d,initialAccountAmount=%d ) error %v", biddingAccount, auctionKey, transactionFee, amountToPay, err)
		return
	}

	curStatus, _ := libGoalClient.Status()
	f.t.Logf("Made and posted a deposit with bid when lastRound was %d", curStatus.LastRound)

	return
}

// CrossVerifyEndOfAuction runs some comparisons on a given params and the assumed next params of the auction, as well as the auction's outcomes
// it returns true if all assertions pass
func (f *AuctionFixture) CrossVerifyEndOfAuction(params auction.Params, outcome auction.BidOutcomes, cancelled bool) (passed bool) {
	passed = true

	//inspect settlement and make sure it is as expected:
	passed = passed && assert.Equal(f.t, params.AuctionID, outcome.AuctionID, "params and outcome should reference same auction ID")
	passed = passed && assert.Equal(f.t, params.AuctionKey, outcome.AuctionKey, "params and outcome should reference same auction key")
	passed = passed && assert.True(f.t, (params.LastPrice*params.MaxPriceMultiple > outcome.Price) || (outcome.Price > params.LastPrice))

	// inspect auction console and make sure it is as expected:
	ac := f.GetAuctionConsoleRestClient()
	bidResponse, err := ac.Bids(outcome.AuctionID)
	passed = passed && assert.NoError(f.t, err)
	if err != nil {
		f.t.Errorf("error getting bids from auction console: %+v", err)
		return
	}
	if !cancelled {
		var winners []string
		for _, outcome := range outcome.Outcomes {
			winners = append(winners, outcome.BidderKey.String())
		}
		for _, bidFromConsole := range bidResponse.Bids {
			passed = passed && assert.Contains(f.t, winners, bidFromConsole.Bidder.String())
		}
	}

	paramsResponse, err := ac.Params(outcome.AuctionID)
	passed = passed && assert.NoError(f.t, err)
	if err != nil {
		f.t.Errorf("error getting params from auction console: %+v", err)
		return
	}
	passed = passed && assert.Equal(f.t, params, paramsResponse.Params)

	return
}

// WaitForNextRound is a utility function to wait for next round
func (f *AuctionFixture) WaitForNextRound() (newAlgodStatus generatedV2.NodeStatusResponse, err error) {
	// get the algod rest client
	algodRestClient := f.GetAlgodRestClient()
	algodStatus, err := algodRestClient.Status()
	if err != nil {
		f.t.Errorf("algodRestClient.Status(): %+v", err)
		return
	}
	newAlgodStatus, err = algodRestClient.StatusAfterBlock(algodStatus.LastRound + 1)
	if err != nil {
		f.t.Errorf("algodRestClient.StatusAfterBlock(%d): %+v", algodStatus.LastRound+1, err)
		return
	}
	return
}

// WaitForNonZeroAuctionID busy-waits for a non-zero auction ID to be seen by the auction console
func (f *AuctionFixture) WaitForNonZeroAuctionID() (lastAuctionID auctionClient.LastAuctionIDResponse, err error) {
	consoleRestClient := f.GetAuctionConsoleRestClient()
	for {
		lastAuctionID, err = consoleRestClient.LastAuctionID()
		if err != nil {
			f.t.Errorf("error calling getLastAuctionID() %v", err)
			break
		} else if lastAuctionID.AuctionID != 0 {
			f.t.Logf("found a nonzero auctionID %+v", lastAuctionID)
			break
		} else {
			f.t.Logf("sleeping in getLastAuctionID()")
			time.Sleep(100000000)
		}
	}
	return
}

// GetAuctionBankPid reads in the auction bank PID
func (f *AuctionFixture) GetAuctionBankPid() (pid string, err error) {

	auctionBankPidFile := filepath.Join(f.rootDir, "AuctionBank", "auctionbank.pid")
	dat, err := ioutil.ReadFile(auctionBankPidFile)
	if err != nil {
		logging.Base().Error(err)
		return
	}
	pid = string(dat)

	pid = strings.TrimSpace(pid)

	return
}

// GetAuctionBankPort reads in the auction bank port
func (f *AuctionFixture) GetAuctionBankPort() (port string, err error) {

	auctionBankPortFile := filepath.Join(f.rootDir, "AuctionBank", "auctionbank.net")
	dat, err := ioutil.ReadFile(auctionBankPortFile)
	if err != nil {
		logging.Base().Error(err)
		return
	}
	port = string(dat)

	port = strings.TrimSpace(port)

	return
}

// GetAuctionConsolePid reads in the auction console PID
func (f *AuctionFixture) GetAuctionConsolePid() (pid string, err error) {

	auctionConsolePidFile := filepath.Join(f.rootDir, "AuctionConsole", "auctionconsole.pid")
	dat, err := ioutil.ReadFile(auctionConsolePidFile)
	if err != nil {
		logging.Base().Error(err)
		return
	}
	pid = string(dat)

	pid = strings.TrimSpace(pid)

	return
}

// GetAuctionConsolePort reads in the auction console port
func (f *AuctionFixture) GetAuctionConsolePort() (port string, err error) {

	auctionConsolePortFile := filepath.Join(f.rootDir, "AuctionConsole", "auctionconsole.net")
	dat, err := ioutil.ReadFile(auctionConsolePortFile)
	if err != nil {
		logging.Base().Error(err)
		return
	}
	port = string(dat)

	port = strings.TrimSpace(port)

	return
}

// GetAuctionMasterPrivateKey reads in the master key file
func (f *AuctionFixture) GetAuctionMasterPrivateKey() (auctionMasterPrivateKey string, err error) {

	auctionMasterPrivateKeyFile := filepath.Join(f.rootDir, "AuctionMaster", "master.key")
	dat, err := ioutil.ReadFile(auctionMasterPrivateKeyFile)
	if err != nil {
		logging.Base().Error(err)
		return
	}

	auctionMasterPrivateKey = strings.TrimSpace(string(dat))
	return
}

// ShowGenesisFile logs the genesis file contents
func (f *AuctionFixture) ShowGenesisFile() (err error) {

	genesisFile := filepath.Join(f.rootDir, "Primary", "genesis.json")
	dat, err := ioutil.ReadFile(genesisFile)
	if err != nil {
		logging.Base().Errorf("Error reading genesis file: %s, with err: %v", genesisFile, err)
		return
	}

	f.t.Logf("Genesis file contents: \n%s", string(dat))
	return
}

// CompareAlgoAndBankAccounts logs some comparative information about a passed username
func (f *AuctionFixture) CompareAlgoAndBankAccounts(userName string) (err error) {

	statusQuery := auctionClient.StatusQuery{
		Username: userName,
	}
	bankAccountInfo, err := f.GetAuctionBankRestClient().AccountStatus(statusQuery)
	if err != nil {
		f.t.Errorf("Error retriving bank account for user name: %s with err:%v", userName, err)
		return
	}
	f.t.Logf("Bank Account for user %s:  %+v", userName, bankAccountInfo)

	libGoalClient := f.GetLibGoalClient()
	algodAccountInfo, err := libGoalClient.AccountInformation(userName)
	if err != nil {
		f.t.Errorf("Error retriving algod account info for account: %s with err:%v", userName, err)
		return
	}

	f.t.Logf("Algod Account for user %s: %+v", userName, algodAccountInfo)

	auctionTracker, err := f.GetAuctionTracker()
	if err != nil {
		f.t.Errorf("Error accessing auction tracker: %v", err)
		return
	}
	f.t.Logf("auctionTracker: %+v", auctionTracker)

	return
}
