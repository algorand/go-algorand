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

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/shared/pingpong"
)

var dataDir string
var srcAddress string
var numAccounts uint32
var minAccountFunds uint64
var maxAmount uint64
var maxFee int64
var minFee uint64
var randomFee, noRandomFee bool
var randomAmount, noRandomAmount bool
var randomDst bool
var runTime string
var refreshTime string
var saveConfig bool
var useDefault bool
var quietish bool
var logicProg string
var randomNote bool
var randomLease bool
var txnPerSec uint64
var teal string
var groupSize uint32
var numAsset uint32
var numApp uint32

/*
Note on box workloads:

two different box workloads are supported in order to exercise different
portions of the performance critical codepath while keeping the app programs
relatively simple. The BoxUpdate workload updates the content of the boxes
during every app call, to verify that box manipulation is performant. The BoxRead
workload only reads the box contents, which requires every box read to work its
way through the in memory state deltas, into the box cache, and potentially all the
way to the database.
*/
var numBoxUpdate uint32
var numBoxRead uint32
var numAppOptIn uint32
var appProgOps uint32
var appProgHashes uint32
var appProgHashSize string
var appProgGlobKeys uint32
var appProgLocalKeys uint32
var duration uint32
var rekey bool
var nftAsaPerSecond uint32
var pidFile string
var cpuprofile string
var randSeed int64
var deterministicKeys bool
var generatedAccountsCount uint64
var generatedAccountsOffset uint64
var generatedAccountSampleMethod string
var configPath string
var latencyPath string
var asyncSending bool

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.PersistentFlags().StringVarP(&dataDir, "datadir", "d", "", "Data directory for the node")

	runCmd.Flags().StringVarP(&srcAddress, "src", "s", "", "Account address to use as funding source for new accounts")
	runCmd.Flags().Uint32VarP(&numAccounts, "numaccounts", "n", 0, "The number of accounts to include in the transfers")
	runCmd.Flags().Uint64VarP(&maxAmount, "ma", "a", 0, "The (max) amount to be transferred")
	runCmd.Flags().Uint64VarP(&minAccountFunds, "minaccount", "", 0, "The minimum amount to fund a test account with")
	runCmd.Flags().Uint64VarP(&txnPerSec, "tps", "t", 0, "Number of Txn per second that pingpong sends")
	runCmd.Flags().Int64VarP(&maxFee, "mf", "f", -1, "The MAX fee to be used for transactions, a value of '0' tells the server to use a suggested fee.")
	runCmd.Flags().Uint64VarP(&minFee, "minf", "m", 1000, "The MIN fee to be used for randomFee transactions")
	runCmd.Flags().BoolVar(&randomAmount, "ra", false, "Set to enable random amounts (up to maxamount)")
	runCmd.Flags().BoolVar(&noRandomAmount, "nra", false, "Set to disable random amounts")
	runCmd.Flags().BoolVar(&randomFee, "rf", false, "Set to enable random fees (between minf and mf)")
	runCmd.Flags().BoolVar(&noRandomFee, "nrf", false, "Set to disable random fees")
	runCmd.Flags().BoolVar(&randomDst, "rd", false, "Send money to randomly-generated addresses")
	runCmd.Flags().StringVar(&runTime, "run", "", "Duration of time (seconds) to run transfers before resting (0 means non-stop)")
	runCmd.Flags().StringVar(&refreshTime, "refresh", "", "Duration of time (seconds) between refilling accounts with money (0 means no refresh)")
	runCmd.Flags().StringVar(&logicProg, "program", "", "File containing the compiled program to include as a logic sig")
	runCmd.Flags().StringVar(&configPath, "config", "", "path to read config json from, or json literal")
	runCmd.Flags().StringVar(&latencyPath, "latency", "", "path to write txn latency log to (.gz for compressed)")
	runCmd.Flags().BoolVar(&saveConfig, "save", false, "Save the effective configuration to disk")
	runCmd.Flags().BoolVar(&useDefault, "reset", false, "Reset to the default configuration (not read from disk)")
	runCmd.Flags().BoolVar(&quietish, "quiet", false, "quietish stdout logging")
	runCmd.Flags().BoolVar(&randomNote, "randomnote", false, "generates a random byte array between 0-1024 bytes long")
	runCmd.Flags().StringVar(&teal, "teal", "", "teal test scenario, can be light, normal, or heavy, this overrides --program")
	runCmd.Flags().Uint32Var(&groupSize, "groupsize", 1, "The number of transactions in each group")
	runCmd.Flags().Uint32Var(&numAsset, "numasset", 0, "The number of assets each account holds")
	runCmd.Flags().Uint32Var(&numApp, "numapp", 0, "The total number of apps to create")
	runCmd.Flags().Uint32Var(&numBoxUpdate, "numboxupdate", 0, "The total number of boxes each app holds, where boxes are updated each app call. Only one of numboxupdate and numboxread can be set")
	runCmd.Flags().Uint32Var(&numBoxRead, "numboxread", 0, "The total number of boxes each app holds, where boxes are only read each app call. Only one of numboxupdate and numboxread can be set.")
	runCmd.Flags().Uint32Var(&numAppOptIn, "numappoptin", 0, "The number of apps each account opts in to")
	runCmd.Flags().Uint32Var(&appProgOps, "appprogops", 0, "The approximate number of TEAL operations to perform in each ApplicationCall transaction")
	runCmd.Flags().Uint32Var(&appProgHashes, "appproghashes", 0, "The number of hashes to include in the Application")
	runCmd.Flags().StringVar(&appProgHashSize, "appproghashsize", "sha256", "The size of hashes to include in the Application")
	runCmd.Flags().Uint32Var(&appProgGlobKeys, "appproggk", 0, "Number of global state writes in the Application")
	runCmd.Flags().Uint32Var(&appProgLocalKeys, "appproglk", 0, "Number of local state writes in the Application. Number or local keys per account will be appproglk / proto.MaxAppTxnAccounts")
	runCmd.Flags().BoolVar(&randomLease, "randomlease", false, "set the lease to contain a random value")
	runCmd.Flags().BoolVar(&rekey, "rekey", false, "Create RekeyTo transactions. Requires groupsize=2 and any of random flags exc random dst")
	runCmd.Flags().Uint32Var(&duration, "duration", 0, "The number of seconds to run the pingpong test, forever if 0")
	runCmd.Flags().BoolVar(&asyncSending, "async", false, "Use async sending mode")
	runCmd.Flags().Uint32Var(&nftAsaPerSecond, "nftasapersecond", 0, "The number of NFT-style ASAs to create per second")
	runCmd.Flags().StringVar(&pidFile, "pidfile", "", "path to write process id of this pingpong")
	runCmd.Flags().StringVar(&cpuprofile, "cpuprofile", "", "write cpu profile to `file`")
	runCmd.Flags().Int64Var(&randSeed, "seed", 0, "input to math/rand.Seed(), defaults to time.Now().UnixNano()")
	runCmd.Flags().BoolVar(&deterministicKeys, "deterministicKeys", false, "Draw from set of netgoal-created accounts using deterministic keys")
	runCmd.Flags().Uint64Var(&generatedAccountsCount, "genaccounts", 0, "The total number of accounts pre-generated by netgoal")
	runCmd.Flags().Uint64Var(&generatedAccountsOffset, "genaccountsoffset", 0, "The initial offset for sampling from the total # of pre-generated accounts")
	runCmd.Flags().StringVar(&generatedAccountSampleMethod, "gensamplemethod", "", "The method of sampling from the total # of pre-generated accounts")
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start running the ping-pong activity",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		// Make a cache dir for wallet handle tokens
		cacheDir, err := os.MkdirTemp("", "pingpong")
		if err != nil {
			reportErrorf("Cannot make temp dir: %v\n", err)
		}
		if cpuprofile != "" {
			proff, profErr := os.Create(cpuprofile)
			if profErr != nil {
				reportErrorf("%s: %v\n", cpuprofile, profErr)
			}
			defer proff.Close()
			profErr = pprof.StartCPUProfile(proff)
			if profErr != nil {
				reportErrorf("%s: StartCPUProfile %v\n", cpuprofile, profErr)
			}
			defer pprof.StopCPUProfile()
		}

		// Get libgoal Client
		ac, err := libgoal.MakeClient(dataDir, cacheDir, libgoal.FullClient)
		if err != nil {
			panic(err)
		}

		if pidFile != "" {
			pidf, pidErr := os.Create(pidFile)
			if pidErr != nil {
				reportErrorf("%s: %v\n", pidFile, pidErr)
			}
			defer os.Remove(pidFile)
			_, pidErr = fmt.Fprintf(pidf, "%d", os.Getpid())
			if pidErr != nil {
				reportErrorf("%s: %v\n", pidFile, pidErr)
			}
			pidErr = pidf.Close()
			if pidErr != nil {
				reportErrorf("%s: %v\n", pidFile, pidErr)
			}
		}

		// Prepare configuration
		dataDirCfgPath := filepath.Join(ac.DataDir(), pingpong.ConfigFilename)
		var cfg pingpong.PpConfig
		if configPath != "" {
			if configPath[0] == '{' {
				// json literal as arg
				cfg = pingpong.DefaultConfig
				lf := strings.NewReader(configPath)
				dec := json.NewDecoder(lf)
				err = dec.Decode(&cfg)
				if err != nil {
					reportErrorf("-config: bad config json, %v", err)
				}
				fmt.Fprintf(os.Stdout, "config from --config:\n")
				cfg.Dump(os.Stdout)
			} else {
				cfg, err = pingpong.LoadConfigFromFile(configPath)
				if err != nil {
					reportErrorf("%s: bad config json, %v", configPath, err)
				}
				fmt.Fprintf(os.Stdout, "config from %#v:\n", configPath)
				cfg.Dump(os.Stdout)
			}
		} else {
			if useDefault {
				cfg = pingpong.DefaultConfig
			} else {
				cfg, err = pingpong.LoadConfigFromFile(dataDirCfgPath)
				if err != nil && !os.IsNotExist(err) {
					reportErrorf("Error loading configuration from '%s': %v\n", dataDirCfgPath, err)
				}
			}
		}

		if randSeed == 0 {
			rand.Seed(time.Now().UnixNano())
		} else {
			rand.Seed(randSeed)
		}

		if srcAddress != "" {
			cfg.SrcAccount = srcAddress
		}
		if numAccounts > 0 {
			cfg.NumPartAccounts = numAccounts
		}
		if maxAmount > 0 {
			cfg.MaxAmt = maxAmount
		}
		if maxFee >= 0 {
			cfg.MaxFee = uint64(maxFee)
		}
		if minFee > 0 {
			cfg.MinFee = minFee
		}
		if minAccountFunds > 0 {
			cfg.MinAccountFunds = minAccountFunds
		}

		if txnPerSec != 0 {
			cfg.TxnPerSec = txnPerSec
		}
		if cfg.TxnPerSec == 0 {
			reportErrorf("cannot set tps to 0")
		}

		if randomFee {
			if cfg.MinFee > cfg.MaxFee {
				reportErrorf("Cannot use randomFee with --minf > --mf.\n")
			}
			cfg.RandomizeFee = true
		}
		if noRandomFee {
			if randomFee {
				reportErrorf("Error --rf and --nrf can't both be specified\n")
			}
			cfg.RandomizeFee = false
		}
		if randomAmount {
			cfg.RandomizeAmt = true
		}
		cfg.RandomLease = randomLease || cfg.RandomLease
		if noRandomAmount {
			if randomAmount {
				reportErrorf("Error --ra and --nra can't both be specified\n")
			}
			cfg.RandomizeAmt = false
		}
		cfg.RandomizeDst = randomDst || cfg.RandomizeDst
		cfg.Quiet = quietish || cfg.Quiet
		if runTime != "" {
			val, err := strconv.ParseUint(runTime, 10, 32)
			if err != nil {
				reportErrorf("Invalid value specified for --run: %v\n", err)
			}
			cfg.RunTime = time.Duration(uint32(val)) * time.Second
		}
		if refreshTime != "" {
			val, err := strconv.ParseUint(refreshTime, 10, 32)
			if err != nil {
				reportErrorf("Invalid value specified for --refresh: %v\n", err)
			}
			cfg.RefreshTime = time.Duration(uint32(val)) * time.Second
		}
		if duration > 0 {
			cfg.MaxRuntime = time.Duration(uint32(duration)) * time.Second
		}
		if asyncSending {
			cfg.AsyncSending = true
		}
		if randomNote {
			cfg.RandomNote = true
		}

		if teal != "" {
			logicProg = ""
			var programStr string
			switch teal {
			case "light":
				programStr = tealLight
			case "normal":
				programStr = tealNormal
				bytes, err := base64.StdEncoding.DecodeString("iZWMx72KvU6Bw6sPAWQFL96YH+VMrBA0XKWD9XbZOZI=")
				if err != nil {
					reportErrorf("Internal error, cannot decode.")
				}
				cfg.LogicArgs = [][]byte{bytes}
			case "heavy":
				programStr = tealHeavy
			default:
				reportErrorf("Invalid argument for --teal: %v\n", teal)
			}
			ops, err := logic.AssembleString(programStr)
			if err != nil {
				ops.ReportMultipleErrors(teal, os.Stderr)
				reportErrorf("Internal error, cannot assemble %v \n", programStr)
			}
			cfg.Program = ops.Program
		}

		if logicProg != "" {
			cfg.Program, err = os.ReadFile(logicProg)
			if err != nil {
				reportErrorf("Error opening logic program: %v\n", err)
			}
		}

		if groupSize > 0 && groupSize <= 16 {
			cfg.GroupSize = groupSize
		} else {
			reportErrorf("Invalid group size: %v\n", groupSize)
		}

		if numAsset == 0 {
			// nop
		} else if numAsset <= 1000 {
			cfg.NumAsset = numAsset
		} else {
			reportErrorf("Invalid number of assets: %d, (valid number: 0 - 1000)\n", numAsset)
		}

		if appProgOps != 0 {
			cfg.AppProgOps = appProgOps
		}
		if appProgHashes != 0 {
			cfg.AppProgHashes = appProgHashes
		}
		if appProgHashSize != "sha256" {
			cfg.AppProgHashSize = appProgHashSize
		}

		if numApp == 0 {
			// nop
		} else if numApp <= 1000 {
			cfg.NumApp = numApp
		} else {
			reportErrorf("Invalid number of apps: %d, (valid number: 0 - 1000)\n", numApp)
		}

		if numAppOptIn > cfg.NumApp {
			reportErrorf("Cannot opt in %d times of %d total apps\n", numAppOptIn, numApp)
		}

		if numAppOptIn != 0 {
			cfg.NumAppOptIn = numAppOptIn
		}

		if appProgGlobKeys > 0 {
			cfg.AppGlobKeys = appProgGlobKeys
		}
		if appProgLocalKeys > 0 {
			cfg.AppLocalKeys = appProgLocalKeys
		}

		// verify and set numBoxUpdate
		if numBoxUpdate != 0 && numApp == 0 {
			reportErrorf("If number of boxes is nonzero than number of apps must also be nonzero")
		}

		if numBoxUpdate <= 8 {
			cfg.NumBoxUpdate = numBoxUpdate
		} else {
			reportErrorf("Invalid number of boxes: %d, (valid number: 0 - 8)\n", numBoxUpdate)
		}

		// verify and set numBoxRead
		if numBoxRead != 0 && numApp == 0 {
			reportErrorf("If number of boxes is nonzero than number of apps must also be nonzero")
		}

		if numBoxRead != 0 && numBoxUpdate != 0 {
			reportErrorf("Only one of numboxread or numboxupdate can be nonzero")
		}

		if numBoxRead <= 8 {
			cfg.NumBoxRead = numBoxRead
		} else {
			reportErrorf("Invalid number of boxes: %d, (valid number: 0 - 8)\n", numBoxRead)
		}

		if rekey {
			cfg.Rekey = rekey
			if !cfg.RandomLease && !cfg.RandomNote && !cfg.RandomizeFee && !cfg.RandomizeAmt {
				reportErrorf("RandomNote, RandomLease, RandomizeFee or RandomizeAmt must be used with rekeying\n")
			}
			if cfg.GroupSize != 2 {
				reportErrorf("Rekeying requires txn groups of size 2\n")
			}
		}

		if nftAsaPerSecond != 0 {
			cfg.NftAsaPerSecond = nftAsaPerSecond
		}

		if deterministicKeys && generatedAccountsCount == 0 {
			reportErrorf("deterministicKeys requires setting generatedAccountsCount")
		}
		if !deterministicKeys && generatedAccountsCount > 0 {
			reportErrorf("generatedAccountsCount requires deterministicKeys=true")
		}
		if deterministicKeys && uint64(numAccounts) > generatedAccountsCount {
			reportErrorf("numAccounts must be <= generatedAccountsCount")
		}
		cfg.DeterministicKeys = deterministicKeys || cfg.DeterministicKeys
		if generatedAccountsCount != 0 {
			cfg.GeneratedAccountsCount = generatedAccountsCount
		}
		if generatedAccountsOffset != 0 {
			cfg.GeneratedAccountsOffset = generatedAccountsOffset
		}
		if generatedAccountSampleMethod != "" {
			cfg.GeneratedAccountSampleMethod = generatedAccountSampleMethod
		}
		// check if numAccounts is greater than the length of the mnemonic list, if provided
		if cfg.DeterministicKeys &&
			len(cfg.GeneratedAccountsMnemonics) > 0 &&
			cfg.NumPartAccounts > uint32(len(cfg.GeneratedAccountsMnemonics)) {
			reportErrorf("numAccounts is greater than number of account mnemonics provided")
		}

		if latencyPath != "" {
			cfg.TotalLatencyOut = latencyPath
		}

		cfg.SetDefaultWeights()
		err = cfg.Check()
		if err != nil {
			reportErrorf("%v", err)
		}

		reportInfof("Preparing to initialize PingPong with config:\n")
		cfg.Dump(os.Stdout)

		pps := pingpong.NewPingpong(cfg)

		// Initialize accounts if necessary
		err = pps.PrepareAccounts(&ac)
		if err != nil {
			reportErrorf("Error preparing accounts for transfers: %v\n", err)
		}

		if saveConfig {
			err = cfg.Save(dataDirCfgPath)
			if err != nil {
				reportErrorf("%s: could not save config, %v\n", dataDirCfgPath, err)
			}
		}

		reportInfof("Preparing to run PingPong with config:\n")
		cfg.Dump(os.Stdout)

		// Kick off the real processing
		pps.RunPingPong(context.Background(), &ac)
	},
}

func reportErrorf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
	os.Exit(1)
}

func reportInfof(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}
