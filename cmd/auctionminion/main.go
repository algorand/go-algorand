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
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"net/url"
	"os"

	"github.com/algorand/go-algorand/auction"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// The auctionminion is a tool that prepares inputs for the auctionmaster,
// which might be offline.  The auctionminion collects the deposits and
// bids for a particular auction ID, figures out which ones are valid
// (by feeding them into the auction logic), and writes the valid ones
// into a file that can be sent to auctionmaster.
//
// The auctionminion is TRUSTED by auctionmaster in two ways:
//
// - It is trusted to provide the full set of valid deposits and bids.
//
// - It is trusted to specify the correct round number in which each
//   deposit and bid occurred.
//
// If the inputs provided to auctionmaster do not satisfy the above
// requirements, the auctionmaster could run an unfair auction (e.g.,
// because some bids were missing, or appeared in a later round).
//
// A side effect of such a compromise is that other users of the system
// might observe the auctionmaster's settlement output to be different
// from what they expected based on the blockchain contents.
//
// However, auctionminion does not have access to auctionmaster's spending
// key, and cannot dispense auction winnings arbitrarily on its own.

var verboseFlag = flag.Bool("verbose", false, "Verbose messages")
var stateFile = flag.String("statefile", "auctionminion.state", "State/config filename")
var initFlag = flag.Bool("init", false, "Initialize state file")

type minionConfig struct {
	AuctionKey basics.Address
	AuctionID  uint64
	StartRound uint64
	AlgodURL   string
	AlgodToken string
}

func writeConfig(cfg minionConfig) error {
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(*stateFile, append(out, '\n'), 0666)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	flag.Parse()

	var cfg minionConfig

	if *initFlag {
		cfg.AlgodURL = "http://127.0.0.1:8080"
		cfg.AuctionID = 1

		err := writeConfig(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot write initial state to %s: %v\n",
				*stateFile, err)
			os.Exit(1)
		}

		fmt.Printf("Wrote initial config/state to %s\n", *stateFile)
		os.Exit(0)
	}

	cfgData, err := ioutil.ReadFile(*stateFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot load state from %s: %v\n",
			*stateFile, err)
		os.Exit(1)
	}

	err = json.Unmarshal(cfgData, &cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot decode state from %s: %v\n",
			*stateFile, err)
		os.Exit(1)
	}

	algodURL, err := url.Parse(cfg.AlgodURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot parse algod URL %s: %v\n", cfg.AlgodURL, err)
		os.Exit(1)
	}

	if cfg.AlgodToken == "" {
		fmt.Fprintf(os.Stderr, "Missing API token in config/state\n")
		os.Exit(1)
	}

	restClient := client.MakeRestClient(*algodURL, cfg.AlgodToken)

	var results []auction.MasterInput
	var ra *auction.RunningAuction
	curRound := cfg.StartRound

	for {
		if ra != nil && curRound > ra.LastRound() {
			break
		}

		if *verboseFlag {
			fmt.Printf("Checking round %d..\n", curRound)
		}

		txns, err := restClient.TransactionsByAddr(cfg.AuctionKey.String(), curRound, curRound, math.MaxUint64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot fetch transactions from %d: %v\n", curRound, err)
			os.Exit(1)
		}

		for _, txn := range txns.Transactions {
			if txn.ConfirmedRound != curRound {
				fmt.Fprintf(os.Stderr, "Confirmed round mismatch: %d != %d\n", txn.ConfirmedRound, curRound)
				os.Exit(1)
			}

			dec := protocol.NewDecoderBytes(txn.Note)

			for {
				var note auction.NoteField
				err = dec.Decode(&note)
				if err != nil {
					break
				}

				switch note.Type {
				case auction.NoteParams:
					if ra != nil {
						continue
					}

					if note.SignedParams.Params.AuctionID != cfg.AuctionID {
						continue
					}

					ra, err = auction.InitSigned(note.SignedParams, crypto.Digest(cfg.AuctionKey))
					if err != nil {
						fmt.Fprintf(os.Stderr, "Failed to initialize auction from round %d: %v\n", curRound, err)
						os.Exit(1)
					}

					fmt.Printf("[%d] Initialized auction %d, deposits @ %d, bids @ %d, last @ %d\n",
						curRound, cfg.AuctionID, ra.Params.DepositRound, ra.Params.FirstRound, ra.LastRound())

				case auction.NoteDeposit:
					if ra == nil {
						fmt.Printf("[%d] Deposit (auction not initialized, skipping)\n", curRound)
						continue
					}

					if err = ra.PlaceSignedDeposit(note.SignedDeposit, curRound); err == nil {
						results = append(results, auction.MasterInput{
							Round:         curRound,
							Type:          auction.NoteDeposit,
							SignedDeposit: note.SignedDeposit,
						})

						fmt.Printf("[%d] Deposit\n", curRound)
					} else {
						fmt.Printf("[%d] Deposit (invalid), err: %v\n", curRound, err)
					}

				case auction.NoteBid:
					if ra == nil {
						fmt.Printf("[%d] Bid (auction not initialized, skipping)\n", curRound)
						continue
					}

					if err = ra.PlaceSignedBid(note.SignedBid, curRound); err == nil {
						results = append(results, auction.MasterInput{
							Round:     curRound,
							Type:      auction.NoteBid,
							SignedBid: note.SignedBid,
						})

						fmt.Printf("[%d] Bid\n", curRound)
					} else {
						fmt.Printf("[%d] Bid (invalid), err: %v\n", curRound, err)
					}

				default:
					continue
				}
			}
		}

		curRound++
	}

	if ra == nil {
		fmt.Fprintf(os.Stderr, "Did not find an auction start transaction for auctionID %d\n", cfg.AuctionID)
		os.Exit(1)
	}

	fmt.Printf("Collected %d auctionmaster inputs\n", len(results))

	outfile := fmt.Sprintf("auction%d.inputs", cfg.AuctionID)
	err = ioutil.WriteFile(outfile, protocol.EncodeReflect(results), 0666)
	if err != nil {
		fmt.Printf("Cannot write to %s: %v\n", outfile, err)
		os.Exit(1)
	}

	fmt.Printf("Wrote auctionmaster inputs into %s\n", outfile)

	cfg.AuctionID++
	cfg.StartRound = ra.LastRound() + 1
	writeConfig(cfg)
	fmt.Printf("Wrote updated state to %s\n", *stateFile)

	outcomes := ra.Settle(false)
	outcomesHash := crypto.HashObj(outcomes)
	fmt.Printf("Expected outcomes hash (if settled without cancelling): %v\n", outcomesHash.String())
}
