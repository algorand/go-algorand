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
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/auction"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// Auction master directory layout; file contents are encoded with
// protocol.Encode() unless otherwise specified.
//
//	master.key		Key seed for signing auction messages (raw 32 bytes)
//	master.pub		ChecksumAddress encoding of master public key
//	initparams.json		JSON encoding of initial parameters
//	initparams.json.tmpl	Template for JSON encoding of initial parameters
//	auction%d.param		auction.SignedParams for auction %d
//	auction%d.multisig	multisigConfig for dispensing address of auction %d
//	auction%d.starttx	transaction.SignedTxn start of auction %d
//	auction%d.inputs	[]auction.MasterInput for auction %d
//	auction%d.outcomes	auction.BidOutcomes for auction %d
//	auction%d.settle	auction.SignedSettlement for auction %d
//	auction%d.settletx	transaction.SignedTxn settlement of auction %d
//	auction%d.paymenttx	concatenation of transaction.SignedTxn for auction %d
//	nextsettlement		uint64 next settlement auction ID
//	lastsettled		ASCII last settled auction ID (for shell scripts)
//	tmp/			Subdirectory used by atomicWrite()

var masterDir = flag.String("dir", "/auction-master", "Master directory")
var initparamsFlag = flag.Bool("initparams", false, "Initialize first auction params")
var skipSigningFlag = flag.Bool("skipsign", false, "Skip signing transactions during settlement")
var cancelAuctionFlag = flag.Bool("cancel", false, "Generates a canceled auction settlement message")

var notesFee = flag.Uint64("notesfee", math.MaxUint64, "Fee for note transactions (start, settle)")
var paymentFee = flag.Uint64("payfee", math.MaxUint64, "Fee for winnings payment transactions")
var txnRound = flag.Uint64("txround", 0, "FirstRound for signed transactions")
var currentVersion = flag.String("currentversion", "", "Current consensus version")
var genHashEnc = flag.String("genhash", "", "Genesis hash")

var genHash crypto.Digest

// multisigConfig describes the preimage of the multisig address used
// to dispense auction winnings.
type multisigConfig struct {
	// This struct gets encoded in two ways.  In the `initparams.json` file,
	// it is JSON-encoded.  We use the natural field names there as the map
	// keys.  It is also encoded in `auction%d.multisig`, using msgpack
	// encoding.  For consistency with our other uses of msgpack, we give
	// the fields explicit names for that encoding.
	Threshold uint8            `codec:"threshold"`
	PKs       []basics.Address `codec:"pks"`
}

// atomicWrite is a wrapper around atomicWriteDir that passes in
// the directory *masterDir, and panics on error.
func atomicWrite(filename string, data []byte) {
	err := atomicWriteDir(*masterDir, filename, data)
	if err != nil {
		panic(fmt.Sprintf("atomicWrite(%s): %v", filename, err))
	}
}

// readFile is a wrapper around ioutil.ReadFile that prefixes
// the directory *masterDir to the filename.
func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filepath.Join(*masterDir, filename))
}

// atomicEncode writes the encoding of [obj] using atomicWrite
func atomicEncode(filename string, obj interface{}) {
	atomicWrite(filename, protocol.EncodeReflect(obj))
}

// readAndDecode reads data from [filename] using readFile, and
// decodes it into [obj].  On error, panic.
func readAndDecode(filename string, obj interface{}) {
	data, err := readFile(filename)
	if err != nil {
		panic(fmt.Sprintf("reading %s: %v", filename, err))
	}

	err = protocol.DecodeReflect(data, obj)
	if err != nil {
		panic(fmt.Sprintf("decoding from %s: %v", filename, err))
	}
}

// readKey reads a key seed file and returns the private key.
func readKey(filename string) *crypto.SignatureSecrets {
	var seed crypto.Seed
	data, err := readFile(filename)
	if err != nil {
		panic(fmt.Sprintf("reading %s: %v", filename, err))
	}

	if len(data) != len(seed) {
		panic(fmt.Sprintf("seed from %s length mismatch: %d != %d", filename, len(data), len(seed)))
	}

	copy(seed[:], data)
	return crypto.GenerateSignatureSecrets(seed)
}

// Helper function to construct a SignedTxn with a specific note field
func noteTxn(masterKey *crypto.SignatureSecrets, note auction.NoteField) transactions.SignedTxn {
	maxTxnLife := config.Consensus[protocol.ConsensusVersion(*currentVersion)].MaxTxnLife
	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      basics.Address(masterKey.SignatureVerifier),
			Fee:         basics.MicroAlgos{Raw: *notesFee},
			FirstValid:  basics.Round(*txnRound),
			LastValid:   basics.Round(*txnRound + maxTxnLife),
			Note:        protocol.Encode(&note),
			GenesisHash: genHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: basics.Address(masterKey.SignatureVerifier),
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}

	return transactions.SignedTxn{
		Txn: txn,
		Sig: masterKey.Sign(txn),
	}
}

type initParams struct {
	auction.Params

	// DispensingMultisig specifies the multisig address from which
	// auction winnings will be distributed.
	DispensingMultisig multisigConfig

	// AuctionKeyDummy overrides the AuctionKey field from Params.
	// We overwrite this value with our own auction public key at init
	// time, and the byte-array representation of AuctionKey in the JSON
	// encoding is distracting.
	AuctionKeyDummy string `json:"AuctionKey"`

	// DispensingKeyDummy overrides the DispensingKey field from Params.
	// We overwrite this value with the hash of the DispensingMultisig
	// at init time, and the byte-array representation of DispensingKey
	// in the JSON encoding is distracting.
	DispensingKeyDummy string `json:"DispensingKey"`

	// BankKey overrides the BankKey field from Params.
	// algod.ChecksumAddress means that the JSON codec will
	// decode it using basics.UnmarshalChecksumAddress.
	BankKey basics.Address `json:"BankKey"`
}

func initAuctionParams() {
	var initParams initParams
	initParams.AuctionKeyDummy = "ignored"
	initParams.DispensingKeyDummy = "ignored"
	initParams.DispensingMultisig.PKs = []basics.Address{}
	jsonTemplate, err := json.MarshalIndent(initParams, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("cannot JSON-encode init params template: %v", err))
	}
	atomicWrite("initparams.json.tmpl", jsonTemplate)

	jsonData, err := readFile("initparams.json")
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Missing initparams.json; use initparams.json.tmpl as template\n")
			os.Exit(1)
		}

		panic(fmt.Sprintf("cannot load initparams.json: %v", err))
	}

	jsonDec := json.NewDecoder(bytes.NewReader(jsonData))
	jsonDec.DisallowUnknownFields()
	err = jsonDec.Decode(&initParams)
	if err != nil {
		panic(fmt.Sprintf("cannot decode initparams.json: %v", err))
	}

	params := initParams.Params

	if params.AuctionID == 0 {
		panic("auction ID cannot be 0")
	}

	if *txnRound == 0 {
		panic("must specify -txround")
	}

	var msigPKs []crypto.PublicKey
	for _, pk := range initParams.DispensingMultisig.PKs {
		msigPKs = append(msigPKs, crypto.PublicKey(pk))
	}
	msigAddr, err := crypto.MultisigAddrGen(1, initParams.DispensingMultisig.Threshold, msigPKs)
	if err != nil {
		panic(fmt.Sprintf("cannot construct multisig address: %v", err))
	}

	masterKey := readKey("master.key")
	params.AuctionKey = crypto.Digest(masterKey.SignatureVerifier)
	params.DispensingKey = msigAddr
	params.BankKey = crypto.Digest(initParams.BankKey)

	signedParams := auction.SignedParams{
		Params: params,
		Sig:    masterKey.Sign(params),
	}

	jsonParamsOut, err := json.MarshalIndent(params, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("cannot JSON-encode params for pretty-printing: %v", err))
	}

	paramNoteTx := noteTxn(masterKey, auction.NoteField{
		Type:         auction.NoteParams,
		SignedParams: signedParams,
	})

	atomicEncode(fmt.Sprintf("auction%d.param", params.AuctionID), signedParams)
	atomicEncode(fmt.Sprintf("auction%d.starttx", params.AuctionID), paramNoteTx)
	atomicEncode(fmt.Sprintf("auction%d.multisig", params.AuctionID), initParams.DispensingMultisig)
	atomicEncode("nextsettlement", params.AuctionID)

	fmt.Printf("Initial auction state:\n%s\n", string(jsonParamsOut))
	fmt.Printf("AuctionKey: %s\n", basics.Address(masterKey.SignatureVerifier).String())
	fmt.Printf("DispensingKey: %s\n", basics.Address(msigAddr).String())
}

func settleAuction() {
	if *txnRound == 0 {
		panic("must specify -txround")
	}

	var auctionID uint64
	readAndDecode("nextsettlement", &auctionID)

	var sp auction.SignedParams
	readAndDecode(fmt.Sprintf("auction%d.param", auctionID), &sp)

	var ins []auction.MasterInput
	readAndDecode(fmt.Sprintf("auction%d.inputs", auctionID), &ins)

	var msigConfig multisigConfig
	readAndDecode(fmt.Sprintf("auction%d.multisig", auctionID), &msigConfig)

	var msigPKs []crypto.PublicKey
	for _, pk := range msigConfig.PKs {
		msigPKs = append(msigPKs, crypto.PublicKey(pk))
	}
	msigBase := crypto.MultisigPreimageFromPKs(1, msigConfig.Threshold, msigPKs)

	// Set up the auction
	ra, err := auction.Init(sp.Params)
	if err != nil {
		panic(fmt.Sprintf("cannot initialize RunningAuction: %v", err))
	}

	// Feed in the inputs
	var lastRound uint64
	for idx, in := range ins {
		if in.Round < lastRound {
			panic(fmt.Sprintf("input %d: round going backwards from %d to %d", idx, lastRound, in.Round))
		}
		lastRound = in.Round

		switch in.Type {
		case auction.NoteDeposit:
			err = ra.PlaceSignedDeposit(in.SignedDeposit, in.Round)
			if err != nil {
				panic(fmt.Sprintf("input %d: invalid deposit, err: %v", idx, err))
			}

		case auction.NoteBid:
			err = ra.PlaceSignedBid(in.SignedBid, in.Round)
			if err != nil {
				panic(fmt.Sprintf("input %d: invalid bid, err: %v", idx, err))
			}

		default:
			panic(fmt.Sprintf("input %d: unknown input type %s", idx, in.Type))
		}
	}

	// Settle the logic
	outcomes := ra.Settle(false)
	settlement := auction.Settlement{
		AuctionKey:   sp.Params.AuctionKey,
		AuctionID:    sp.Params.AuctionID,
		Cleared:      outcomes.Cleared,
		OutcomesHash: crypto.HashObj(outcomes),
	}
	atomicEncode(fmt.Sprintf("auction%d.outcomes", auctionID), outcomes)

	if !*skipSigningFlag {
		masterKey := readKey("master.key")

		signedSettlement := auction.SignedSettlement{
			Settlement: settlement,
			Sig:        masterKey.Sign(settlement),
		}

		settleNoteTx := noteTxn(masterKey, auction.NoteField{
			Type:             auction.NoteSettlement,
			SignedSettlement: signedSettlement,
		})

		atomicEncode(fmt.Sprintf("auction%d.settle", auctionID), signedSettlement)
		atomicEncode(fmt.Sprintf("auction%d.settletx", auctionID), settleNoteTx)
	}

	// Construct payments
	var paymentData []byte
	for idx, winner := range outcomes.Outcomes {
		// Include a distinct note in case there are multiple
		// winning bids by the same bidder for the same amount.
		note := make([]byte, crypto.DigestSize+24)
		binary.LittleEndian.PutUint64(note[0:8], winner.BidID)
		copy(note[8:crypto.DigestSize+8], sp.Params.AuctionKey[:])
		binary.LittleEndian.PutUint64(note[crypto.DigestSize+8:crypto.DigestSize+16], sp.Params.AuctionID)
		binary.LittleEndian.PutUint64(note[crypto.DigestSize+16:crypto.DigestSize+24], uint64(idx))

		maxTxnLife := config.Consensus[protocol.ConsensusVersion(*currentVersion)].MaxTxnLife
		txn := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      basics.Address(sp.Params.DispensingKey),
				Fee:         basics.MicroAlgos{Raw: *paymentFee},
				FirstValid:  basics.Round(*txnRound),
				LastValid:   basics.Round(*txnRound + maxTxnLife),
				Note:        note,
				GenesisHash: genHash,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: basics.Address(winner.WinningsAddress),
				Amount:   basics.MicroAlgos{Raw: winner.AlgosWon},
			},
		}

		signedTx := transactions.SignedTxn{
			Txn:  txn,
			Msig: msigBase,
		}

		paymentData = append(paymentData, protocol.Encode(&signedTx)...)
	}

	atomicWrite(fmt.Sprintf("auction%d.paymenttx", auctionID), paymentData)

	// For shell scripts that deal with the output of auctionmaster,
	// write an ASCII-encoded auction ID of the last settled auction.
	atomicWrite("lastsettled", []byte(fmt.Sprintf("%d\n", sp.Params.AuctionID)))

	// Commit point: write nextsettlement
	atomicEncode("nextsettlement", auctionID+1)
}

func cancelAuction() {
	if *txnRound == 0 {
		panic("must specify -txround")
	}

	var auctionID uint64
	readAndDecode("nextsettlement", &auctionID)

	var sp auction.SignedParams
	readAndDecode(fmt.Sprintf("auction%d.param", auctionID), &sp)

	// Set up the auction
	ra, err := auction.Init(sp.Params)
	if err != nil {
		panic(fmt.Sprintf("cannot initialize RunningAuction: %v", err))
	}

	// Settle the logic
	outcomes := ra.Settle(true)
	settlement := auction.Settlement{
		AuctionKey:   sp.Params.AuctionKey,
		AuctionID:    sp.Params.AuctionID,
		Cleared:      outcomes.Cleared,
		OutcomesHash: crypto.HashObj(outcomes),
		Canceled:     true,
	}
	atomicEncode(fmt.Sprintf("auction%d.outcomes", auctionID), outcomes)

	if !*skipSigningFlag {
		masterKey := readKey("master.key")

		signedSettlement := auction.SignedSettlement{
			Settlement: settlement,
			Sig:        masterKey.Sign(settlement),
		}

		settleNoteTx := noteTxn(masterKey, auction.NoteField{
			Type:             auction.NoteSettlement,
			SignedSettlement: signedSettlement,
		})

		atomicEncode(fmt.Sprintf("auction%d.settle", auctionID), signedSettlement)
		atomicEncode(fmt.Sprintf("auction%d.settletx", auctionID), settleNoteTx)
	}

	// For shell scripts that deal with the output of auctionmaster,
	// write an ASCII-encoded auction ID of the last settled auction.
	atomicWrite("lastsettled", []byte(fmt.Sprintf("%d\n", sp.Params.AuctionID)))

	// Commit point: write nextsettlement
	atomicEncode("nextsettlement", auctionID+1)
}

func main() {
	flag.Parse()

	validateFlags()

	if *cancelAuctionFlag {
		cancelAuction()
	} else {

		if *initparamsFlag {
			initAuctionParams()
		} else {
			settleAuction()
		}
	}
}

func validateFlags() {
	// Validate required flags
	if *paymentFee == math.MaxUint64 {
		panic("payfee is required and should be 0 or more than the current minimum transaction fee")
	}

	if *notesFee == math.MaxUint64 {
		panic("notesfee is required and should be 0 or more than the current minimum transaction fee")
	}

	if *currentVersion == "" {
		panic("currentversion is required and should be valid for the duration of the auction")
	}
	_, ok := config.Consensus[protocol.ConsensusVersion(*currentVersion)]
	if !ok {
		panic(fmt.Sprintf("currentversion '%s' not supported by this auctionmaster", *currentVersion))
	}

	if *genHashEnc == "" {
		panic("genhash is required")
	}
	ghash, err := base64.StdEncoding.DecodeString(*genHashEnc)
	if err != nil {
		panic(fmt.Sprintf("genhash '%s' is not a valid base64 encoding: %v", ghash, err))
	}
	if len(ghash) != 32 {
		panic(fmt.Sprintf("genhash '%s' has length %d", ghash, len(ghash)))
	}
	copy(genHash[:], ghash)
}
