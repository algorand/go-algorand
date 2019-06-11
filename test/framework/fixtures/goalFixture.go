// Copyright (C) 2019 Algorand, Inc.
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

func (f *GoalFixture) executeCommand(args ...string) (ret string, err error) {
	cmd := filepath.Join(f.binDir, goalCmd)
	// We always execute goal against the PrimaryDataDir() instance
	args = append(args, "-d", f.PrimaryDataDir())
	ret, err = util.ExecAndCaptureOutput(cmd, args...)
	ret = strings.TrimRight(ret, "\n")
	//fmt.Printf("command: %v %v\nret: %v\n", cmd, args, ret)
	return
}

// AccountNew exposes the `goal account new` command
func (f *GoalFixture) AccountNew(name string) (address string, err error) {
	ret, err := f.executeCommand(accountCmd, newCmd, name)

	if err != nil {
		if strings.Contains(ret, "is already taken") {
			return "", ErrAccountAlreadyTaken
		}
		return
	}
	valid := strings.HasPrefix(ret, "Created new account with address")
	if !valid {
		return "", ErrAccountNewCall
	}
	lastSpaceIndex := strings.LastIndexByte(ret, ' ')
	if lastSpaceIndex < 0 {
		return "", fmt.Errorf("invalid account result: %s", ret)
	}
	address = string(ret[lastSpaceIndex+1:])
	return
}

// AccountRename exposes the `goal account rename` command
func (f *GoalFixture) AccountRename(name, newName string) (err error) {
	ret, err := f.executeCommand(accountCmd, renameCmd, name, newName)
	if err != nil {
		return
	}

	if strings.Contains(ret, "Renamed") {
		return nil
	}

	return fmt.Errorf("error processing rename: %s", ret)
}

// CheckAccountListContainsAccount processes the `goal account list` results and returns true
// if the provided matcher matches one of the results
func (f *GoalFixture) CheckAccountListContainsAccount(matcher func([]string) bool) (bool, error) {
	ret, err := f.executeCommand(accountCmd, listCmd)
	if err != nil {
		return false, err
	}

	accounts := strings.Split(ret, "\n")
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
func (f *GoalFixture) NodeStart() (err error) {
	var ret string
	ret, err = f.executeCommand(nodeCmd, startCmd)
	if err != nil {
		return
	}
	if !strings.Contains(ret, "Algorand node successfully started") {
		err = fmt.Errorf("failed to start node: %s", ret)
	}
	return
}

// NodeStop exposes the `goal node stop` command
func (f *GoalFixture) NodeStop() (err error) {
	var ret string
	ret, err = f.executeCommand(nodeCmd, stopCmd)
	if err != nil {
		return
	}
	if !strings.Contains(ret, "The node was successfully stopped") {
		err = fmt.Errorf("failed to stop node: %s", ret)
	}
	return
}

// ClerkSend exposes the `goal clerk send` command with a plaintext note
func (f *GoalFixture) ClerkSend(from, to string, amount, fee int64, note string) (txID string, err error) {
	// Successful send returns response in form of:
	// Sent <amt> algos from account <from> to address <to>, transaction ID: tx-<txID>. Fee set to <fee>
	var ret string
	ret, err = f.executeCommand(clerkCmd, sendCmd,
		fromParam, from,
		toParam, to,
		feeParam, strconv.FormatInt(fee, 10),
		amountParam, strconv.FormatInt(amount, 10),
		noteParam, note)
	if err != nil {
		return
	}
	return parseClerkSendResponse(ret)
}

// ClerkSendNoteb64 exposes the `goal clerk send` command but passes the note as base64
func (f *GoalFixture) ClerkSendNoteb64(from, to string, amount, fee int64, noteb64 string) (txID string, err error) {
	// Successful send returns response in form of:
	// Sent <amt> algos from account <from> to address <to>, transaction ID: tx-<txID>. Fee set to <fee>
	var ret string
	ret, err = f.executeCommand(clerkCmd, sendCmd,
		fromParam, from,
		toParam, to,
		feeParam, strconv.FormatInt(fee, 10),
		amountParam, strconv.FormatInt(amount, 10),
		noteb64Param, noteb64)
	if err != nil {
		return
	}

	return parseClerkSendResponse(ret)
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
	_, err = f.executeCommand(args...)
	return
}
