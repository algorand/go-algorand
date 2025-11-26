// Copyright (C) 2019-2025 Algorand, Inc.
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
	"maps"
	"os"
	"slices"
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
	firstValid  basics.Round
	lastValid   basics.Round
	network     string
	offline     bool
	txFile      string
	partkeyFile string
	addr        string
}

// There is no node to query, so we do our best here.
const (
	txnLife = 1000
	minFee  = 1000
)

var validNetworks map[string]crypto.Digest
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
	keyregCmd.Flags().Uint64Var((*uint64)(&params.firstValid), "firstvalid", 0, "first round where the transaction may be committed to the ledger")
	if err := keyregCmd.MarkFlagRequired("firstvalid"); err != nil {
		panic(err)
	}
	keyregCmd.Flags().Uint64Var((*uint64)(&params.lastValid), "lastvalid", 0, fmt.Sprintf("last round where the generated transaction may be committed to the ledger, defaults to firstvalid + %d", txnLife))
	keyregCmd.Flags().StringVar(&params.network, "network", "mainnet", "the network where the provided keys will be registered, one of mainnet/testnet/betanet")
	if err := keyregCmd.MarkFlagRequired("network"); err != nil {
		panic(err)
	}
	keyregCmd.Flags().BoolVar(&params.offline, "offline", false, "set to bring an account offline")
	keyregCmd.Flags().StringVarP(&params.txFile, "outputFile", "o", "", fmt.Sprintf("write signed transaction to this file, or '%s' to write to stdout", stdoutFilenameValue))
	keyregCmd.Flags().StringVar(&params.partkeyFile, "keyfile", "", "participation keys to register, file is opened to fetch metadata for the transaction; only specify when bringing an account online to vote in Algorand consensus")
	keyregCmd.Flags().StringVar(&params.addr, "account", "", "account address to bring offline; only specify when taking an account offline from voting in Algorand consensus")

	// TODO: move 'bundleGenesisInject' into something that can be imported here instead of using constants.
	validNetworks = map[string]crypto.Digest{
		"mainnet": mustConvertB64ToDigest("wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="),
		"testnet": mustConvertB64ToDigest("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="),
		"betanet": mustConvertB64ToDigest("mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0="),
		"devnet":  mustConvertB64ToDigest("sC3P7e2SdbqKJK0tbiCdK9tdSpbe6XeCGKdoNzmlj0E="),
	}
	validNetworkList = slices.Collect(maps.Keys(validNetworks))
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

func getGenesisInformation(network string) (crypto.Digest, error) {
	// For testing purposes, there is a secret option to override the genesis information.
	hashOverride := os.Getenv("ALGOKEY_GENESIS_HASH")
	if hashOverride != "" {
		return mustConvertB64ToDigest(hashOverride), nil
	}

	// Otherwise check that network matches one of the known networks.
	gen, ok := validNetworks[strings.ToLower(network)]
	if !ok {
		return crypto.Digest{}, fmt.Errorf("unknown network '%s' provided. Supported networks: %s",
			network,
			strings.Join(validNetworkList, ", "))
	}

	return gen, nil
}

func run(params keyregCmdParams) error {
	// Implicit last valid
	if params.lastValid == 0 {
		params.lastValid = params.firstValid + txnLife
	}

	if params.fee < minFee {
		return fmt.Errorf("the provided transaction fee (%d) is too low, the minimum fee is %d", params.fee, minFee)
	}

	if !params.offline {
		if params.partkeyFile == "" {
			return errors.New("must provide --keyfile when registering participation keys")
		}
		if params.addr != "" {
			return errors.New("do not provide --account when registering participation keys")
		}
	} else {
		if params.addr == "" {
			return errors.New("must provide --account when bringing an account offline")
		}
		if params.partkeyFile != "" {
			return errors.New("do not provide --keyfile when bringing an account offline")
		}
	}

	var accountAddress basics.Address
	if params.addr != "" {
		var err error
		accountAddress, err = basics.UnmarshalChecksumAddress(params.addr)
		if err != nil {
			return fmt.Errorf("unable to parse --account: %w", err)
		}
	}

	if params.partkeyFile != "" && !util.FileExists(params.partkeyFile) {
		return fmt.Errorf("cannot access keyfile '%s'", params.partkeyFile)
	}

	if params.txFile == "" {
		params.txFile = fmt.Sprintf("%s.tx", params.partkeyFile)
	}

	if params.txFile != stdoutFilenameValue && util.FileExists(params.txFile) {
		return fmt.Errorf("outputFile '%s' already exists", params.txFile)
	}

	// Lookup information from partkey file
	var part *account.Participation
	if params.partkeyFile != "" {
		partDB, err := db.MakeErasableAccessor(params.partkeyFile)
		if err != nil {
			return fmt.Errorf("cannot open keyfile %s: %v", params.partkeyFile, err)
		}

		partkey, err := account.RestoreParticipation(partDB)
		if err != nil {
			return fmt.Errorf("cannot load keyfile %s: %v", params.partkeyFile, err)
		}
		defer partkey.Close()

		part = &partkey.Participation

		if params.firstValid < part.FirstValid {
			return fmt.Errorf("the transaction's firstvalid round (%d) field should be set greater than or equal to the participation key's first valid round (%d). The network will reject key registration transactions that are set to take effect before the participation key's first valid round", params.firstValid, part.FirstValid)
		}
	}

	validRange := params.lastValid - params.firstValid
	if validRange > txnLife {
		return fmt.Errorf("the transaction's specified validity range must be less than or equal to 1000 rounds due to security constraints. Please enter a first valid round (%d) and last valid round (%d) whose difference is no more than 1000 rounds", params.firstValid, params.lastValid)
	}

	var txn transactions.Transaction
	if !params.offline {
		// Generate go-online transaction
		txn = part.GenerateRegistrationTransaction(
			basics.MicroAlgos{Raw: params.fee},
			params.firstValid, params.lastValid,
			[32]byte{},
			part.StateProofSecrets != nil)
	} else {
		// Generate go-offline transaction
		txn = transactions.Transaction{
			Type: protocol.KeyRegistrationTx,
			Header: transactions.Header{
				Sender:     accountAddress,
				Fee:        basics.MicroAlgos{Raw: params.fee},
				FirstValid: params.firstValid,
				LastValid:  params.lastValid,
			},
		}
	}

	var err error
	txn.GenesisHash, err = getGenesisInformation(params.network)
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
		if err = os.WriteFile(params.txFile, data, 0600); err != nil {
			return fmt.Errorf("failed to write transaction to '%s': %w", params.txFile, err)
		}
	}

	if params.offline {
		fmt.Printf("Account key go offline transaction written to '%s'.\n", params.txFile)
	} else {
		fmt.Printf("Key registration transaction written to '%s'.\n", params.txFile)
	}
	return nil
}
