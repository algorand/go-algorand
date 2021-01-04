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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/libgoal"
)

// AccountsList holds a mapping between the account's address, its friendly name and whether it's a default one.
type AccountsList struct {
	Accounts        map[string]string
	DefaultAccount  string
	DefaultWalletID string
	DataDir         string
}

func makeAccountsList(dataDir string) *AccountsList {
	acctList := &AccountsList{
		DataDir:  dataDir,
		Accounts: map[string]string{},
	}
	acctList.loadList()
	return acctList
}

func isValidName(name string) (bool, string) {
	if _, err := basics.UnmarshalChecksumAddress(name); err == nil {
		return false, "An Algorand address cannot be used as an account name."
	}
	return true, ""
}

func (accountList *AccountsList) accountListFileName() string {
	dataDir := accountList.DataDir
	client := ensureGoalClient(dataDir, libgoal.DynamicClient)
	gid, err := client.GenesisID()
	if err != nil {
		reportErrorln(fmt.Sprintf(errorGenesisIDFail, err, dataDir))
	}
	if libgoal.AlgorandDataIsPrivate(dataDir) {
		return filepath.Join(dataDir, gid, "accountList.json")
	}
	cu, err := user.Current()
	if err != nil {
		reportErrorln("could not get current user info")
	}
	return filepath.Join(cu.HomeDir, ".algorand", gid, "accountList.json")
}

// isDefault returns true, if the account is marked is default, false otherwise. If account doesn't exist isDefault
// return false
func (accountList *AccountsList) isDefault(accountAddress string) bool {
	return accountList.DefaultAccount == accountAddress
}

func (accountList *AccountsList) setDefaultWalletID(ID []byte) {
	// Update the default ID
	accountList.DefaultWalletID = string(ID)
	accountList.dumpList()
}

func (accountList *AccountsList) getDefaultWalletID() []byte {
	return []byte(accountList.DefaultWalletID)
}

// setDefault sets the account to default
func (accountList *AccountsList) setDefault(accountName string) {
	// Get account address
	for address, name := range accountList.Accounts {
		if name == accountName {
			accountList.DefaultAccount = address
			break
		}
	}

	accountList.dumpList()
}

// isTaken checks if the account friendly name is already being used by another account
func (accountList *AccountsList) isTaken(accountName string) bool {
	for _, name := range accountList.Accounts {
		if name == accountName {
			return true
		}
	}
	return false
}

// rename renames account's friendly name
func (accountList *AccountsList) rename(oldName, newName string) {
	for addr, name := range accountList.Accounts {
		if name == oldName {
			accountList.Accounts[addr] = newName
			break
		}
	}
	accountList.dumpList()
}

// getUnnamed returns the next available unnamed string
func (accountList *AccountsList) getUnnamed() string {
	var highest int
	var proposedName string

	for {
		proposedName = fmt.Sprintf("Unnamed-%d", highest)
		if !accountList.isTaken(proposedName) {
			return proposedName
		}
		highest++
	}
}

// addAccount adds a new address to accounts list
func (accountList *AccountsList) addAccount(accountName, address string) {
	if ok, err := isValidName(accountName); !ok {
		fmt.Println(err)
		return
	}

	if len(accountList.Accounts) == 0 {
		accountList.DefaultAccount = address
	}

	accountList.Accounts[address] = accountName

	accountList.dumpList()
}

// removeAccount removes an address from the accounts list
func (accountList *AccountsList) removeAccount(address string) {
	delete(accountList.Accounts, address)
	accountList.dumpList()
}

// getDefaultAccount returns the default account address
func (accountList *AccountsList) getDefaultAccount() string {
	return accountList.DefaultAccount
}

// getAddressByName returns an account name given its address. If it doesn't exist, it returns the name itself
func (accountList *AccountsList) getAddressByName(accountName string) string {
	for address, name := range accountList.Accounts {
		if name == accountName {
			return address
		}
	}
	return accountName
}

// getNameByAddress returns an account address given its name. If it doesn't exist, it returns the address itself
func (accountList *AccountsList) getNameByAddress(address string) string {
	if name, ok := accountList.Accounts[address]; ok {
		return name
	}
	return address
}

// dumpList dumps the account list into the json file
func (accountList *AccountsList) dumpList() {
	accountsListJSON, _ := json.MarshalIndent(accountList, "", "  ")
	accountsListJSON = append(accountsListJSON, '\n')
	err := ioutil.WriteFile(accountList.accountListFileName(), accountsListJSON, 0644)

	if err != nil {
		log.Error(err.Error())
		fmt.Print(err.Error())
	}
}

// loadList loads the account list from the json file, if the latter doesn't exist, it creates a new *in-memory* one.
func (accountList *AccountsList) loadList() {
	// First, check if the file exists.
	filename := accountList.accountListFileName()
	if _, err := os.Stat(filename); err == nil {
		raw, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Error(err.Error())
		}
		json.Unmarshal(raw, &accountList)
	}
}

func (accountList *AccountsList) outputAccount(addr string, acctInfo v1.Account, multisigInfo *libgoal.MultisigInfo) {
	if acctInfo.Address == "" {
		fmt.Printf("[n/a]\t%s\t%s\t[n/a] microAlgos", accountList.getNameByAddress(addr), addr)
	} else {
		var status string
		switch acctInfo.Status {
		case basics.Online.String():
			status = "online"
		case basics.Offline.String():
			status = "offline"
		case basics.NotParticipating.String():
			status = "excluded"
		default:
			panic(fmt.Sprintf("unexpected account status: %v", acctInfo.Status))
		}
		fmt.Printf("[%s]\t%s\t%s\t%d microAlgos", status, accountList.getNameByAddress(addr), addr, acctInfo.Amount)
	}
	if multisigInfo != nil {
		fmt.Printf("\t[%d/%d multisig]", multisigInfo.Threshold, len(multisigInfo.PKs))
	}
	if len(acctInfo.AssetParams) > 0 {
		var out []string
		for curid, params := range acctInfo.AssetParams {
			_, unitName := unicodePrintable(params.UnitName)
			out = append(out, fmt.Sprintf("%d (%d %s)", curid, params.Total, unitName))
		}
		fmt.Printf("\t[created asset IDs: %s]", strings.Join(out, ", "))
	}
	if len(acctInfo.AppParams) > 0 {
		var out []string
		for aid := range acctInfo.AppParams {
			out = append(out, fmt.Sprintf("%d", aid))
		}
		fmt.Printf("\t[created app IDs: %s]", strings.Join(out, ", "))
	}
	if len(acctInfo.AppLocalStates) > 0 {
		var out []string
		for aid := range acctInfo.AppLocalStates {
			out = append(out, fmt.Sprintf("%d", aid))
		}
		fmt.Printf("\t[opted in app IDs: %s]", strings.Join(out, ", "))
	}

	if accountList.isDefault(addr) {
		fmt.Printf("\t*Default")
	}
	fmt.Print("\n")
}
