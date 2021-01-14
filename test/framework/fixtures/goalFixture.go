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
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/util"
)

// GoalFixture is a fixture for tests against the goal CLI
type GoalFixture struct {
	RestClientFixture
}

// ErrAccountAlreadyTaken indicates account new is called with a duplicate / existing friendly account name
var ErrAccountAlreadyTaken = fmt.Errorf("account name already taken")

// ErrAccountNewCall indicates the account new REST call failed
var ErrAccountNewCall = fmt.Errorf("account new failed")

const (
	goalCmd = "goal"

	accountCmd       = "account"
	listCmd          = "list"
	newCmd           = "new"
	renameCmd        = "rename"
	importRootKeyCmd = "importrootkey"

	clerkCmd     = "clerk"
	sendCmd      = "send"
	amountParam  = "-a"
	feeParam     = "--fee"
	fromParam    = "-f"
	noteParam    = "-n"
	noteb64Param = "--noteb64"
	toParam      = "-t"

	nodeCmd  = "node"
	startCmd = "start"
	stopCmd  = "stop"
)

func (f *GoalFixture) executeCommand(args ...string) (retStdout string, retStderr string, err error) {
	cmd := filepath.Join(f.binDir, goalCmd)
	// We always execute goal against the PrimaryDataDir() instance
	args = append(args, "-d", f.PrimaryDataDir())
	retStdout, retStderr, err = util.ExecAndCaptureOutput(cmd, args...)
	retStdout = strings.TrimRight(retStdout, "\n")
	retStderr = strings.TrimRight(retStderr, "\n")
	//fmt.Printf("command: %v %v\nret: %v\n", cmd, args, ret)
	return
}

// combine the error and the output so that we could return it as a single error object.
func combineExecuteError(retStdout string, retStderr string, err error) error {
	if err == nil {
		return err
	}
	return fmt.Errorf("%v\nStdout:\n%s\nStderr:\n%s", err, retStdout, retStderr)
}

// AccountNew exposes the `goal account new` command
func (f *GoalFixture) AccountNew(name string) (address string, err error) {
	stdout, stderr, err := f.executeCommand(accountCmd, newCmd, name)

	if err != nil {
		if strings.Contains(stderr, "is already taken") {
			return "", ErrAccountAlreadyTaken
		}
		return "", combineExecuteError(stdout, stderr, err)
	}
	valid := strings.HasPrefix(stdout, "Created new account with address")
	if !valid {
		return "", ErrAccountNewCall
	}
	lastSpaceIndex := strings.LastIndexByte(stdout, ' ')
	if lastSpaceIndex < 0 {
		return "", fmt.Errorf("invalid account result: %s", stdout)
	}
	address = stdout[lastSpaceIndex+1:]
	return
}

// AccountRename exposes the `goal account rename` command
func (f *GoalFixture) AccountRename(name, newName string) (err error) {
	stdout, stderr, err := f.executeCommand(accountCmd, renameCmd, name, newName)
	if err != nil {
		return combineExecuteError(stdout, stderr, err)
	}

	if strings.Contains(stdout, "Renamed") {
		return nil
	}

	return fmt.Errorf("error processing rename: %s", stderr)
}

// CheckAccountListContainsAccount processes the `goal account list` results and returns true
// if the provided matcher matches one of the results
func (f *GoalFixture) CheckAccountListContainsAccount(matcher func([]string) bool) (bool, error) {
	stdout, stderr, err := f.executeCommand(accountCmd, listCmd)
	if err != nil {
		return false, combineExecuteError(stdout, stderr, err)
	}

	accounts := strings.Split(stdout, "\n")
	if len(accounts) == 0 {
		return false, nil
	}

	for _, row := range accounts {
		elements := strings.Split(row, "\t")
		if len(elements) >= 4 { // Valid Account entries should include 4 components (status, name, address, balance)
			if matcher(elements) {
				return true, nil
			}
		}
	}
	return false, nil
}

// NodeStart exposes the `goal node start` command
func (f *GoalFixture) NodeStart() error {
	stdout, stderr, err := f.executeCommand(nodeCmd, startCmd)
	if err != nil {
		return combineExecuteError(stdout, stderr, err)
	}
	if !strings.Contains(stdout, "Algorand node successfully started") {
		err = fmt.Errorf("failed to start node: %s", stderr)
	}
	return err
}

// NodeStop exposes the `goal node stop` command
func (f *GoalFixture) NodeStop() error {
	stdout, stderr, err := f.executeCommand(nodeCmd, stopCmd)
	if err != nil {
		return combineExecuteError(stdout, stderr, err)
	}
	if !strings.Contains(stdout, "The node was successfully stopped") {
		err = fmt.Errorf("failed to stop node: %s", stderr)
	}
	return err
}

// ClerkSend exposes the `goal clerk send` command with a plaintext note
func (f *GoalFixture) ClerkSend(from, to string, amount, fee int64, note string) (string, error) {
	// Successful send returns response in form of:
	// Sent <amt> algos from account <from> to address <to>, transaction ID: tx-<txID>. Fee set to <fee>
	stdout, stderr, err := f.executeCommand(clerkCmd, sendCmd,
		fromParam, from,
		toParam, to,
		feeParam, strconv.FormatInt(fee, 10),
		amountParam, strconv.FormatInt(amount, 10),
		noteParam, note)
	if err != nil {
		return "", combineExecuteError(stdout, stderr, err)
	}
	return parseClerkSendResponse(stdout)
}

// ClerkSendNoteb64 exposes the `goal clerk send` command but passes the note as base64
func (f *GoalFixture) ClerkSendNoteb64(from, to string, amount, fee int64, noteb64 string) (string, error) {
	// Successful send returns response in form of:
	// Sent <amt> algos from account <from> to address <to>, transaction ID: tx-<txID>. Fee set to <fee>
	stdout, stderr, err := f.executeCommand(clerkCmd, sendCmd,
		fromParam, from,
		toParam, to,
		feeParam, strconv.FormatInt(fee, 10),
		amountParam, strconv.FormatInt(amount, 10),
		noteb64Param, noteb64)
	if err != nil {
		return "", combineExecuteError(stdout, stderr, err)
	}

	return parseClerkSendResponse(stdout)
}

func parseClerkSendResponse(ret string) (txID string, err error) {
	if strings.HasPrefix(ret, "Sent ") {
		txIndex := strings.Index(ret, "ID: ")
		if txIndex > 0 {
			// Extract "tx-<txid>" string
			txID = ret[txIndex+4:]
			txID = txID[:52] // 52 is the len of txid
			return
		}
	}
	err = fmt.Errorf("unable to parse txid from response: %s", ret)
	return
}

// AccountImportRootKey exposes the `goal account importrootkey` command
func (f *GoalFixture) AccountImportRootKey(wallet string, createDefaultUnencrypted bool) (err error) {
	if wallet == "" {
		wallet = string(libgoal.UnencryptedWalletName)
	}
	args := []string{
		accountCmd,
		importRootKeyCmd,
		"-w",
		wallet,
	}
	if createDefaultUnencrypted {
		args = append(args, "-u")
	}
	_, _, err = f.executeCommand(args...)
	return
}
