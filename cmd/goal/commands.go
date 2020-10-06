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
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"golang.org/x/crypto/ssh/terminal"

	algodclient "github.com/algorand/go-algorand/daemon/algod/api/client"
	kmdclient "github.com/algorand/go-algorand/daemon/kmd/client"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/common"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var log = logging.Base()

var dataDirs []string

var defaultCacheDir = "goal.cache"

var verboseVersionPrint bool

var kmdDataDirFlag string

var versionCheck bool

func init() {
	// infile
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().BoolVarP(&verboseVersionPrint, "verbose", "v", false, "Print all version info available")
	rootCmd.Flags().BoolVarP(&versionCheck, "version", "v", false, "Display and write current build version and exit")
	rootCmd.AddCommand(licenseCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(protoCmd)

	// account.go
	rootCmd.AddCommand(accountCmd)

	// wallet.go
	rootCmd.AddCommand(walletCmd)

	// clerk.go
	rootCmd.AddCommand(clerkCmd)

	// asset.go
	rootCmd.AddCommand(assetCmd)

	// node.go
	rootCmd.AddCommand(nodeCmd)

	// kmd.go
	rootCmd.AddCommand(kmdCmd)

	// logging.go
	rootCmd.AddCommand(loggingCmd)

	// network.go
	rootCmd.AddCommand(networkCmd)

	// ledger.go
	rootCmd.AddCommand(ledgerCmd)

	// completion.go
	rootCmd.AddCommand(completionCmd)

	// application.go
	rootCmd.AddCommand(appCmd)

	// Config
	defaultDataDirValue := []string{""}
	rootCmd.PersistentFlags().StringArrayVarP(&dataDirs, "datadir", "d", defaultDataDirValue, "Data directory for the node")
	rootCmd.PersistentFlags().StringVarP(&kmdDataDirFlag, "kmddir", "k", "", "Data directory for kmd")
}

var rootCmd = &cobra.Command{
	Use:   "goal",
	Short: "CLI for interacting with Algorand",
	Long:  `GOAL is the CLI for interacting Algorand software instance. The binary 'goal' is installed alongside the algod binary and is considered an integral part of the complete installation. The binaries should be used in tandem - you should not try to use a version of goal with a different version of algod.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		if versionCheck {
			fmt.Println(config.FormatVersionAndLicense())
			return
		}
		//If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

// Write commands to exercise all subcommands with `-h`
// Can be used to check that there are no conflicts in arguments between inner and outer commands.
func runAllHelps(c *cobra.Command, out io.Writer) (err error) {
	if c.Runnable() {
		cmd := c.CommandPath() + " -h\n"
		_, err = out.Write([]byte(cmd))
		if err != nil {
			return
		}
	}
	for _, sub := range c.Commands() {
		err = runAllHelps(sub, out)
		if err != nil {
			return
		}
	}
	return
}

func main() {
	// Hidden command to generate docs in a given directory
	// goal generate-docs [path]
	if len(os.Args) == 3 && os.Args[1] == "generate-docs" {
		err := doc.GenMarkdownTree(rootCmd, os.Args[2])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		os.Exit(0)
	} else if len(os.Args) == 2 && os.Args[1] == "helptest" {
		// test that subcommands don't have arg conflicts:
		// goal helptest | bash -x -e
		runAllHelps(rootCmd, os.Stdout)
		os.Exit(0)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "The current version of the Algorand daemon (algod)",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		onDataDirs(func(dataDir string) {
			response, err := ensureAlgodClient(dataDir).AlgodVersions()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			if !verboseVersionPrint {
				fmt.Println(response.Versions)
				return
			}
			fmt.Printf("Version: %v \n", response.Versions)
			fmt.Printf("GenesisID: %s \n", response.GenesisID)
			if (response.Build != common.BuildVersion{}) {
				fmt.Printf("Build: %d.%d.%d.%s [%s] (commit #%s)\n", response.Build.Major, response.Build.Minor, response.Build.BuildNumber, response.Build.Channel, response.Build.Branch, response.Build.CommitHash)
			}
		})
	},
}

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "Display license information",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(config.GetLicenseInfo())
	},
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "",
	Long:  "Produces report helpful for debugging.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(config.FormatVersionAndLicense())
		fmt.Println()
		data, err := exec.Command("uname", "-a").CombinedOutput()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(string(data))

		dirs := getDataDirs()
		report := len(dirs) > 1
		for _, dir := range dirs {
			if report {
				reportInfof(infoDataDir, dir)
			}
			genesis, err := readGenesis(dir)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Printf("Genesis ID from genesis.json: %s\n", genesis.ID())
		}
		fmt.Println()
		onDataDirs(getStatus)
	},
}

var protoCmd = &cobra.Command{
	Use:   "protocols",
	Short: "",
	Long:  "Dump standard consensus protocols as json to stdout.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		os.Stdout.Write(protocol.EncodeJSON(config.Consensus))
	},
}

func readGenesis(dataDir string) (genesis bookkeeping.Genesis, err error) {
	path := filepath.Join(dataDir, config.GenesisJSONFile)
	genesisText, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	err = protocol.DecodeJSON(genesisText, &genesis)
	return
}

// -k || $ALGORAND_KMD || old location in algod data dir if it is a 'private' dev algo data dir || ~/.algorand/{genesis id}/kmd-{kmd version}
func resolveKmdDataDir(dataDir string) string {
	if kmdDataDirFlag != "" {
		out, _ := filepath.Abs(kmdDataDirFlag)
		return out
	}
	kmdDataDirEnv := os.Getenv("ALGORAND_KMD")
	if kmdDataDirEnv != "" {
		out, _ := filepath.Abs(kmdDataDirEnv)
		return out
	}
	if dataDir == "" {
		dataDir = resolveDataDir()
	}
	if libgoal.AlgorandDataIsPrivate(dataDir) {
		algodKmdPath, _ := filepath.Abs(filepath.Join(dataDir, libgoal.DefaultKMDDataDir))
		return algodKmdPath
	}
	cu, err := user.Current()
	if err != nil {
		reportErrorf("could not look up current user while looking for kmd dir: %s", err)
	}
	if cu.HomeDir == "" {
		reportErrorln("user has no home dir while looking for kmd dir")
	}
	genesis, err := readGenesis(dataDir)
	if err != nil {
		reportErrorf("could not read genesis.json: %s", err)
	}
	return filepath.Join(cu.HomeDir, ".algorand", genesis.ID(), libgoal.DefaultKMDDataDir)
}

func resolveDataDir() string {
	// Figure out what data directory to tell algod to use.
	// If not specified on cmdline with '-d', look for default in environment.
	var dir string
	if len(dataDirs) > 0 {
		dir = dataDirs[0]
	}
	if dir == "" {
		dir = os.Getenv("ALGORAND_DATA")
	}
	return dir
}

func ensureFirstDataDir() string {
	// Get the target data directory to work against,
	// then handle the scenario where no data directory is provided.
	dir := resolveDataDir()
	if dir == "" {
		reportErrorln(errorNoDataDirectory)
	}
	return dir
}

func ensureSingleDataDir() string {
	if len(dataDirs) > 1 {
		reportErrorln(errorOneDataDirSupported)
	}
	return ensureFirstDataDir()
}

// like ensureSingleDataDir() but doesn't exit()
func maybeSingleDataDir() string {
	if len(dataDirs) > 1 {
		return ""
	}
	return resolveDataDir()
}

func getDataDirs() (dirs []string) {
	if len(dataDirs) == 0 {
		reportErrorln(errorNoDataDirectory)
	}
	dirs = append(dirs, ensureFirstDataDir())
	dirs = append(dirs, dataDirs[1:]...)
	return
}

func onDataDirs(action func(dataDir string)) {
	dirs := getDataDirs()
	report := len(dirs) > 1

	for _, dir := range dirs {
		if report {
			reportInfof(infoDataDir, dir)
		}
		action(dir)
	}
}

func ensureCacheDir(dataDir string) string {
	var err error
	if libgoal.AlgorandDataIsPrivate(dataDir) {
		cacheDir := filepath.Join(dataDir, defaultCacheDir)
		err = os.Mkdir(cacheDir, 0700)
		if err != nil && !os.IsExist(err) {
			reportErrorf("could not make cachedir: %s", err)
		}
		return cacheDir
	}
	// Put the cache in the user's home directory
	algorandDir, err := config.GetDefaultConfigFilePath()
	if err != nil {
		reportErrorf("config error %s", err)
	}
	dataDirEscaped := strings.ReplaceAll(dataDir, "/", "_")
	cacheDir := filepath.Join(algorandDir, dataDirEscaped)
	err = os.MkdirAll(cacheDir, 0700)
	if err != nil {
		reportErrorf("could not make cachedir: %s", err)
	}
	return cacheDir
}

func ensureKmdClient(dataDir string) libgoal.Client {
	return ensureGoalClient(dataDir, libgoal.KmdClient)
}

func ensureAlgodClient(dataDir string) libgoal.Client {
	return ensureGoalClient(dataDir, libgoal.AlgodClient)
}

func ensureFullClient(dataDir string) libgoal.Client {
	return ensureGoalClient(dataDir, libgoal.FullClient)
}

func ensureGoalClient(dataDir string, clientType libgoal.ClientType) libgoal.Client {
	clientConfig := libgoal.ClientConfig{
		AlgodDataDir: dataDir,
		KMDDataDir:   resolveKmdDataDir(dataDir),
		CacheDir:     ensureCacheDir(dataDir),
	}
	client, err := libgoal.MakeClientFromConfig(clientConfig, clientType)
	if err != nil {
		reportErrorf(errorNodeStatus, err)
	}
	client.SetAPIVersionAffinity(algodclient.APIVersionV2, kmdclient.APIVersionV1)
	return client
}

func ensureWalletHandle(dataDir string, walletName string) []byte {
	wh, _ := ensureWalletHandleMaybePassword(dataDir, walletName, false)
	return wh
}

func ensureWalletHandleMaybePassword(dataDir string, walletName string, getPassword bool) (wh []byte, pw []byte) {
	wh, pw, err := getWalletHandleMaybePassword(dataDir, walletName, getPassword)
	if err != nil {
		reportErrorln(err)
	}

	return wh, pw
}

func getWalletHandleMaybePassword(dataDir string, walletName string, getPassword bool) (wh []byte, pw []byte, err error) {
	var walletID []byte
	var dup bool

	accountList := makeAccountsList(dataDir)
	kmd := ensureKmdClient(dataDir)

	// If the user didn't manually specify a wallet, use the default wallet ID
	if walletName == "" {
		walletID = accountList.getDefaultWalletID()
		if len(walletID) == 0 {
			// If we still don't have a default, check if there's only one wallet.
			// If there is, make it the default and continue
			wallets, err := kmd.ListWallets()
			if err != nil {
				return nil, nil, fmt.Errorf(errCouldNotListWallets, err)
			}
			if len(wallets) == 1 {
				// Only one wallet, so it's unambigious
				walletID = []byte(wallets[0].ID)
				accountList.setDefaultWalletID(walletID)
			} else if len(wallets) == 0 {
				return nil, nil, fmt.Errorf(errNoWallets)
			} else {
				return nil, nil, fmt.Errorf(errNoDefaultWallet)
			}
		}
		// Fetch the wallet name (useful for error messages, and to check
		// that the default wallet hasn't disappeared)
		var wnBytes []byte
		wnBytes, dup, err = kmd.FindWalletNameByID(walletID)
		if dup {
			return nil, nil, fmt.Errorf(errWalletIDDuplicate, walletID)
		}
		if err != nil {
			return nil, nil, fmt.Errorf(errGettingWalletName, walletID, err)
		}
		if len(wnBytes) == 0 {
			return nil, nil, fmt.Errorf(errDefaultWalletNotFound, walletID)
		}
		walletName = string(wnBytes)
	} else {
		// The user manually specified a wallet, so look up the ID
		walletID, dup, err = kmd.FindWalletIDByName([]byte(walletName))
		if err != nil {
			return nil, nil, fmt.Errorf(errFindingWallet, err)
		}
		if dup {
			return nil, nil, fmt.Errorf(errWalletNameAmbiguous, walletName)
		}
	}

	// If walletID is still blank, we couldn't find the wallet
	if len(walletID) == 0 {
		return nil, nil, fmt.Errorf(errWalletNotFound, walletName)
	}

	// Try getting a cached token, authing with a blank password if required
	token, err := kmd.GetWalletHandleTokenCached(walletID, nil)
	if err == nil {
		if getPassword && !kmd.WalletIsUnencrypted(walletID) {
			return token, ensurePasswordForWallet(walletName), nil
		}
		return token, nil, nil
	}

	// Assume any errors were "wrong password" errors, until we have actual
	// API error codes
	pw = ensurePasswordForWallet(walletName)

	// Try fetching the wallet again, this time with a password
	token, err = kmd.GetWalletHandleTokenCached(walletID, pw)
	if err != nil {
		return nil, nil, fmt.Errorf(errGettingToken, walletName, walletID, err)
	}
	return token, pw, nil
}

func ensurePasswordForWallet(walletName string) []byte {
	password, ok := os.LookupEnv("ALGORAND_KMD_PASSWORD")
	if ok {
		return []byte(password)
	}
	fmt.Printf(infoPasswordPrompt, walletName)
	return ensurePassword()
}

func ensurePassword() []byte {
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		reportErrorf(errorFailedToReadPassword, err)
	}
	fmt.Printf("\n")
	return password
}

func reportInfoln(args ...interface{}) {
	fmt.Println(args...)
	// log.Infoln(args...)
}

func reportInfof(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
	// log.Infof(format, args...)
}

func reportWarnln(args ...interface{}) {
	fmt.Print("Warning: ")
	fmt.Println(args...)
	// log.Warnln(args...)
}

func reportWarnf(format string, args ...interface{}) {
	fmt.Printf("Warning: "+format+"\n", args...)
	// log.Warnf(format, args...)
}

func reportErrorln(args ...interface{}) {
	fmt.Fprintln(os.Stderr, args...)
	// log.Warnln(args...)
	os.Exit(1)
}

func reportErrorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	// log.Warnf(format, args...)
	os.Exit(1)
}

// writeFile is a wrapper of ioutil.WriteFile which considers the special
// case of stdout filename
func writeFile(filename string, data []byte, perm os.FileMode) error {
	var err error
	if filename == stdoutFilenameValue {
		// Write to Stdout
		if _, err = os.Stdout.Write(data); err != nil {
			return err
		}
		return nil
	}
	return ioutil.WriteFile(filename, data, perm)
}

// readFile is a wrapper of ioutil.ReadFile which consniders the
// special case of stdin filename
func readFile(filename string) ([]byte, error) {
	if filename == stdinFileNameValue {
		return ioutil.ReadAll(os.Stdin)
	}
	return ioutil.ReadFile(filename)
}

func checkTxValidityPeriodCmdFlags(cmd *cobra.Command) {
	validRoundsChanged := cmd.Flags().Changed("validrounds") || cmd.Flags().Changed("validRounds")
	if validRoundsChanged && cmd.Flags().Changed("lastvalid") {
		reportErrorf("Only one of [--validrounds] or [--lastvalid] can be specified")
	}
	if validRoundsChanged && numValidRounds == 0 {
		reportErrorf("[--validrounds] can not be zero")
	}
}
