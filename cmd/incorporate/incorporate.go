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

// incorporate builds a genesis JSON file from a CSV file.
//
// The CSV file is read from stdin, the JSON file is emitted at stdout,
// and metadata parameters (schema ID, network, version, genesis time)
// are echoed on stderr.
package main

import (
	"encoding/base64"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/codecs"
)

var idName = flag.String("s", "", "The schema ID for this ledger.")
var netName = flag.String("n", "", "The name of the network for this ledger.")
var versionName = flag.String("v", "", "The consensus protocol version string for this ledger.")
var genesisTime = flag.Int64("t", 0, "The starting Unix timestamp for this ledger (current time if not given).")
var metadataFile = flag.String("m", "", "JSON Metatdata file for genesis metadata.")
var comment = flag.String("c", "", "Genesis Comment")

var allegedOutput = flag.String("x", "", "If given, verify against the given JSON file instead of generating.")

func main() {
	flag.Parse()

	genesis := parseInput()
	validateGenesis(genesis)

	if *allegedOutput == "" {
		log.Println("Genesis block created with parameters")
		echoArgs()
		fmt.Println(string(protocol.EncodeJSON(genesis)))
	} else {
		log.Fatal("TODO validation not supported yet!")
		//   if !validateAgainst(*allegedOutput) {
		//   	log.Fatalf("file mismatch")
		//   }
	}
}

func validateInput(genesis bookkeeping.Genesis) {
	if genesis.SchemaID == "" {
		log.Fatalf("schema ID not given")
	}

	if genesis.Network == "" {
		log.Fatalf("network name not given")
	}

	if genesis.Proto == "" {
		log.Fatalf("version name not given")
	}
}

func validateGenesis(genesis bookkeeping.Genesis) {
	if len(genesis.Allocation) < 3 {
		log.Fatalf("too few allocations in genesis")
	}

	if genesis.Allocation[0].Comment != "RewardsPool" {
		log.Fatalf("first account not rewards pool")
	}
	if genesis.Allocation[1].Comment != "FeeSink" {
		log.Fatalf("second account not fee sink")
	}

	if genesis.Allocation[0].State.Status != basics.NotParticipating {
		log.Fatalf("rewards pool is participating")
	}
	if genesis.Allocation[1].State.Status != basics.NotParticipating {
		log.Fatalf("fee sink is participating")
	}

	atLeastOneOnline := false
	for _, alloc := range genesis.Allocation {
		if alloc.State.Status == basics.Online {
			atLeastOneOnline = true
			if alloc.State.VoteFirstValid != 0 {
				log.Fatalf("account %s has nonzero VoteFirstValid: %d != 0", alloc.Address, alloc.State.VoteFirstValid)
			}
		}

		if alloc.State.MicroAlgos.Raw < config.Consensus[genesis.Proto].MinBalance {
			log.Fatalf("account %s has less than MinBalance: %d < %d", alloc.Address, alloc.State.MicroAlgos.Raw, config.Consensus[genesis.Proto].MinBalance)
		}
	}

	if !atLeastOneOnline {
		log.Fatalf("no online accounts")
	}
}

func echoArgs() {
	log.Printf("  schema ID:    %s", *idName)
	log.Printf("  network name: %s", *netName)
	log.Printf("  version name: %s", *versionName)
	log.Printf("  genesis time: %d", *genesisTime)
}

//   func validateAgainst(string) bool { return false }

func parseInput() (genesis bookkeeping.Genesis) {
	if *metadataFile != "" {
		var err error
		genesis, err = parseMetadata(*metadataFile)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		genesis.SchemaID = *idName
		genesis.Network = protocol.NetworkID(*netName)
		genesis.Proto = protocol.ConsensusVersion(*versionName)
		genesis.Comment = *comment
	}
	genesis.Timestamp = *genesisTime

	validateInput(genesis)

	r := csv.NewReader(os.Stdin)
	i := 0
	for {
		i++

		row, err := r.Read()
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Fatal(err)
		}

		if i == 1 {
			// header line
			continue
		}

		record := parseRecord(row)

		switch i {
		case 2:
			genesis.RewardsPool = record.Address
		case 3:
			genesis.FeeSink = record.Address
		}

		alloc := bookkeeping.GenesisAllocation{
			Address: record.Address,
			Comment: record.Comment,
			State: basics.AccountData{
				Status:          record.Status,
				MicroAlgos:      basics.MicroAlgos{Raw: record.Algos * 1e6},
				VoteID:          record.VoteID,
				SelectionID:     record.SelectionID,
				VoteFirstValid:  basics.Round(record.VoteFirstValid),
				VoteLastValid:   basics.Round(record.VoteLastValid),
				VoteKeyDilution: record.VoteKeyDilution,
			},
		}
		genesis.Allocation = append(genesis.Allocation, alloc)
	}
}

// GenesisMetadata stores metadata for genesis.json creation
type GenesisMetadata struct {
	Network           string
	SchemaID          string
	ConsensusProtocol string
	Comment           string
}

func parseMetadata(metadataFile string) (genesis bookkeeping.Genesis, err error) {
	var metadata GenesisMetadata
	err = codecs.LoadObjectFromFile(metadataFile, &metadata)
	if err != nil {
		err = fmt.Errorf("error loading metadata file '%s': %s", metadataFile, err)
		return
	}
	genesis.Network = protocol.NetworkID(metadata.Network)
	genesis.SchemaID = metadata.SchemaID
	genesis.Proto = protocol.ConsensusVersion(metadata.ConsensusProtocol)
	genesis.Comment = metadata.Comment
	return
}

func parseRecord(cols []string) (rec record) {
	var err error

	if len(cols) < 9 {
		log.Fatal("fewer than 9 columns in cols")
	}

	rec.Comment = cols[0]
	rec.Address = cols[1]

	stake := strings.Replace(cols[2], ",", "", -1)
	stake = strings.TrimSpace(stake)
	rec.Algos, err = strconv.ParseUint(stake, 10, 64)
	if err != nil {
		log.Fatal(err)
	}

	switch cols[3] {
	case "Online":
		rec.Status = basics.Online
	case "Offline":
		rec.Status = basics.Offline
	case "NotParticipating":
		rec.Status = basics.NotParticipating
	default:
		log.Fatalf("unknown status: %s", cols[3])
	}

	if rec.Status != basics.Online {
		for i := 4; i <= 8; i++ {
			if cols[i] != "" {
				log.Fatalf("account offline but cols[%d] set", i)
			}
		}
		return
	}

	sel, err := base64.StdEncoding.DecodeString(cols[4])
	if err != nil {
		log.Fatal(err)
	}
	copy(rec.SelectionID[:], sel)
	vote, err := base64.StdEncoding.DecodeString(cols[5])
	if err != nil {
		log.Fatal(err)
	}
	copy(rec.VoteID[:], vote)

	rec.VoteFirstValid, err = strconv.ParseUint(cols[6], 10, 64)
	if cols[6] != "" && err != nil {
		log.Fatal(err)
	}
	rec.VoteLastValid, err = strconv.ParseUint(cols[7], 10, 64)
	if cols[7] != "" && err != nil {
		log.Fatal(err)
	}
	rec.VoteKeyDilution, err = strconv.ParseUint(cols[8], 10, 64)
	if cols[8] != "" && err != nil {
		log.Fatal(err)
	}

	return
}

type record struct {
	Comment         string
	Address         string
	Algos           uint64
	Status          basics.Status
	SelectionID     crypto.VRFVerifier
	VoteID          crypto.OneTimeSignatureVerifier
	VoteFirstValid  uint64
	VoteLastValid   uint64
	VoteKeyDilution uint64
}
