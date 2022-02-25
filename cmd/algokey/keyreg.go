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
	online      bool
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

func init() {
	var params keyregCmdParams

	keyregCmd = &cobra.Command{
		Use:   "keyreg",
		Short: "Make key registration transaction",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			err := Run(params)
			if err != nil {
				fmt.Fprintf(os.Stderr, err.Error())
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
	keyregCmd.Flags().BoolVar(&params.online, "online", true, "set account to online or offline")
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
}

func mustConvertB64ToDigest(b64 string) (digest crypto.Digest) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to decode digest '%s': %s", b64, err)
		os.Exit(1)
	}
	if len(data) != len(digest[:]) {
		fmt.Fprintf(os.Stderr, "Unexpected decoded digest length decoding '%s'.", b64)
		os.Exit(1)
	}
	copy(digest[:], data)
	return
}

func Run(params keyregCmdParams) error {
	validNetworkList := make([]string, 0, len(validNetworks))
	for k, _ := range validNetworks {
		validNetworkList = append(validNetworkList, k)
	}

	// Implicit last valid
	if params.lastValid == 0 {
		params.lastValid = params.firstValid + txnLife
	}

	if params.online {
		if params.partkeyFile == "" {
			return errors.New("must provide --partkey-file when registering participation keys")
		}
		if params.addr != "" {
			return errors.New("do not provide --address when registering participation keys")
		}
	} else {
		if params.addr != "" {
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

	if !util.FileExists(params.partkeyFile) {
		return fmt.Errorf("cannot access partkey-file '%s'", params.partkeyFile)
	}

	if util.FileExists(params.txFile) || params.txFile == stdoutFilenameValue {
		return fmt.Errorf("tx-file '%s' already exists", params.partkeyFile)
	}

	// Lookup information from partkey file
	var part *account.Participation
	if params.partkeyFile != "" {
		partdb, err := db.MakeErasableAccessor(params.partkeyFile)
		if err != nil {
			return fmt.Errorf("cannot open partkey %s: %v", params.partkeyFile, err)
		}

		partkey, err := account.RestoreParticipation(partdb)
		if err != nil {
			return fmt.Errorf("Cannot load partkey %s: %v", params.partkeyFile, err)
		}

		part = &partkey.Participation
		//accountAddress = part.Parent
		//keyFirstValid = part.FirstValid
		//keyLastValid = part.LastValid
	}

	if params.firstValid < uint64(part.FirstValid) {
		return fmt.Errorf("first-valid (%d) is earlier than the key first valid (%d)", params.firstValid, part.FirstValid)
	}

	validRange := params.lastValid - params.firstValid
	if validRange > txnLife {
		return fmt.Errorf("first-valid (%d) is %d greater than last-valid (%d). last-valid may not be greater than first-valid + %d", params.firstValid, validRange, params.lastValid, txnLife)
	}

	var txn transactions.Transaction
	if params.online {
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

	gen, ok := validNetworks[strings.ToLower(params.network)]
	if !ok {
		return fmt.Errorf("unknown network '%s' provided. Supported networks: %s",
			params.network,
			strings.Join(validNetworkList, ", "))
	}

	txn.GenesisID = gen.id
	txn.GenesisHash = gen.hash

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

	return nil
}