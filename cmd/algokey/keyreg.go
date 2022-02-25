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
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/db"
)

var keyregCmd *cobra.Command

type keyregCmdParams struct {
	fee         uint64
	firstValid  uint64
	lastValid   uint64
	network     string
	offline     bool
	txFile      string
	partkeyFile string
	addr        string
}

// There is no node to query, so we do our best here.
const (
	txnLife uint64 = 1000
	minFee  uint64 = 1000
)

type networkGenesis struct {
	id   string
	hash crypto.Digest
}

var validNetworks map[string]networkGenesis
var validNetworkList []string

func init() {
	var params keyregCmdParams

	keyregCmd = &cobra.Command{
		Use:   "keyreg",
		Short: "Make key registration transaction",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			err := run(params)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n\n", err.Error())
				os.Exit(1)
			}
		},
	}

	keyregCmd.Flags().Uint64Var(&params.fee, "fee", minFee, "transaction fee")
	keyregCmd.Flags().Uint64Var(&params.firstValid, "first-valid", 0, "first round where the transaction may be committed to the ledger")
	keyregCmd.MarkFlagRequired("first-valid")
	keyregCmd.Flags().Uint64Var(&params.lastValid, "last-valid", 0, fmt.Sprintf("last round where the generated transaction may be committed to the ledger, defaults to first-valid + %d", txnLife))
	keyregCmd.Flags().StringVar(&params.network, "network", "mainnet", "the network where the provided keys will be registered, one of mainnet/testnet/betanet")
	keyregCmd.MarkFlagRequired("network")
	keyregCmd.Flags().BoolVar(&params.offline, "offline", false, "set to bring an account offline")
	keyregCmd.Flags().StringVar(&params.txFile, "tx-file", "", fmt.Sprintf("write signed transaction to this file, or '%s' to write to stdout", stdoutFilenameValue))
	keyregCmd.MarkFlagRequired("tx-file")
	keyregCmd.Flags().StringVar(&params.partkeyFile, "partkey-file", "", "participation keys to register, file is opened to fetch metadata for the transaction, mutually exclusive with account")
	keyregCmd.Flags().StringVar(&params.addr, "account", "", "account address to bring offline, mutually exclusive with partkey-file")

	// TODO: move 'bundleGenesisInject' into something that can be imported here instead of using constants.
	validNetworks = map[string]networkGenesis{
		"mainnet": {
			id:   "mainnet-v1",
			hash: mustConvertB64ToDigest("wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=")},
		"testnet": {
			id:   "testnet-v1",
			hash: mustConvertB64ToDigest("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=")},
		"betanet": {
			id:   "betanet-v1",
			hash: mustConvertB64ToDigest("mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0=")},
		"devnet": {
			id:   "devnet-v1",
			hash: mustConvertB64ToDigest("sC3P7e2SdbqKJK0tbiCdK9tdSpbe6XeCGKdoNzmlj0E=")},
	}
	validNetworkList = make([]string, 0, len(validNetworks))
	for k := range validNetworks {
		validNetworkList = append(validNetworkList, k)
	}
}

func mustConvertB64ToDigest(b64 string) (digest crypto.Digest) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to decode digest '%s': %s\n\n", b64, err)
		os.Exit(1)
	}
	if len(data) != len(digest[:]) {
		fmt.Fprintf(os.Stderr, "Unexpected decoded digest length decoding '%s'.\n\n", b64)
		os.Exit(1)
	}
	copy(digest[:], data)
	return
}

func getGenesisInformation(network string) (string, crypto.Digest, error) {
	// For testing purposes, there is a secret option to override the genesis information.
	idOverride := os.Getenv("ALGOKEY_GENESIS_ID")
	hashOverride := os.Getenv("ALGOKEY_GENESIS_HASH")
	if idOverride != "" && hashOverride != "" {
		return idOverride, mustConvertB64ToDigest(hashOverride), nil
	}

	// Otherwise check that network matches one of the known networks.
	gen, ok := validNetworks[strings.ToLower(network)]
	if !ok {
		return "", crypto.Digest{}, fmt.Errorf("unknown network '%s' provided. Supported networks: %s",
			network,
			strings.Join(validNetworkList, ", "))
	}

	return gen.id, gen.hash, nil
}

func run(params keyregCmdParams) error {
	// Implicit last valid
	if params.lastValid == 0 {
		params.lastValid = params.firstValid + txnLife
	}

	if !params.offline {
		if params.partkeyFile == "" {
			return errors.New("must provide --partkey-file when registering participation keys")
		}
		if params.addr != "" {
			return errors.New("do not provide --address when registering participation keys")
		}
	} else {
		if params.addr == "" {
			return errors.New("must provide --address when bringing an account offline")
		}
		if params.partkeyFile != "" {
			return errors.New("do not provide --partkey-file when bringing an account offline")
		}
	}

	var accountAddress basics.Address
	if params.addr != "" {
		var err error
		accountAddress, err = basics.UnmarshalChecksumAddress(params.addr)
		if err != nil {
			return fmt.Errorf("unable to parse --address: %w", err)
		}
	}

	if params.partkeyFile != "" && !util.FileExists(params.partkeyFile) {
		return fmt.Errorf("cannot access partkey-file '%s'", params.partkeyFile)
	}

	if util.FileExists(params.txFile) || params.txFile == stdoutFilenameValue {
		return fmt.Errorf("tx-file '%s' already exists", params.partkeyFile)
	}

	// Lookup information from partkey file
	var part *account.Participation
	if params.partkeyFile != "" {
		partDB, err := db.MakeErasableAccessor(params.partkeyFile)
		if err != nil {
			return fmt.Errorf("cannot open partkey %s: %v", params.partkeyFile, err)
		}

		partkey, err := account.RestoreParticipation(partDB)
		if err != nil {
			return fmt.Errorf("cannot load partkey %s: %v", params.partkeyFile, err)
		}

		part = &partkey.Participation
		//accountAddress = part.Parent
		//keyFirstValid = part.FirstValid
		//keyLastValid = part.LastValid

		if params.firstValid < uint64(part.FirstValid) {
			return fmt.Errorf("first-valid (%d) is earlier than the key first valid (%d)", params.firstValid, part.FirstValid)
		}
	}


	validRange := params.lastValid - params.firstValid
	if validRange > txnLife {
		return fmt.Errorf("first-valid (%d) is %d greater than last-valid (%d). last-valid may not be greater than first-valid + %d", params.firstValid, validRange, params.lastValid, txnLife)
	}

	var txn transactions.Transaction
	if !params.offline {
		// Generate go-online transaction
		txn = part.GenerateRegistrationTransaction(
			basics.MicroAlgos{Raw: params.fee},
			basics.Round(params.firstValid),
			basics.Round(params.lastValid),
			[32]byte{},
			part.StateProofSecrets != nil)
	} else {
		// Generate go-offline transaction
		txn = transactions.Transaction{
			Type: protocol.KeyRegistrationTx,
			Header: transactions.Header{
				Sender:     accountAddress,
				Fee:        basics.MicroAlgos{Raw: params.fee},
				FirstValid: basics.Round(params.firstValid),
				LastValid:  basics.Round(params.lastValid),
			},
		}
	}

	var err error
	txn.GenesisID, txn.GenesisHash, err = getGenesisInformation(params.network)
	if err != nil {
		return err
	}

	// Wrap in a transactions.SignedTxn with an empty sig.
	// This way protocol.Encode will encode the transaction type
	stxn, err := transactions.AssembleSignedTxn(txn, crypto.Signature{}, crypto.MultisigSig{})
	if err != nil {
		return fmt.Errorf("failed to assemble transaction: %w", err)
	}

	data := protocol.Encode(&stxn)
	if params.txFile == stdoutFilenameValue {
		// Write to Stdout
		if _, err = os.Stdout.Write(data); err != nil {
			return fmt.Errorf("failed to write transaction to stdout: %w", err)
		}
	} else {
		ioutil.WriteFile(params.txFile, data, 0600)
	}

	if params.offline {
		fmt.Printf("Account key unregister transaction written to '%s'.\n", params.txFile)
	} else {
		fmt.Printf("Key registration transaction written to '%s'.\n", params.txFile)
	}
	return nil
}
