// Copyright (C) 2019-2024 Algorand, Inc.
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

package pingpong

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/algorand/go-algorand/util/codecs"
)

// ConfigFilename name of configuration file
const ConfigFilename = "ppconfig.json"

// PpConfig defines configuration structure for
type PpConfig struct {
	// SrcAccount is address to use as funding source for new accounts
	SrcAccount      string
	RandomizeFee    bool
	RandomizeAmt    bool
	RandomizeDst    bool
	MaxRandomDst    uint64
	MaxFee          uint64
	MinFee          uint64
	MaxAmt          uint64
	TxnPerSec       uint64
	NumPartAccounts uint32
	RunTime         time.Duration
	RefreshTime     time.Duration
	MinAccountFunds uint64
	Quiet           bool
	RandomNote      bool
	RandomLease     bool
	TotalLatencyOut string

	Program            []byte
	LogicArgs          [][]byte
	ProgramProbability float64

	GroupSize uint32
	// NumAsset is the number of assets each account holds
	NumAsset uint32
	// MinAccountAsset
	MinAccountAsset uint64
	// NumApp is the total number of apps to create
	NumApp uint32
	// NumAppOptIn is the number of apps each account opts in to
	NumAppOptIn uint32
	// NumBoxUpdate is the number of boxes used per app, where box values are updated each call
	NumBoxUpdate uint32
	// NumBoxRead is the number of boxes used per app, where box values are only read each call
	NumBoxRead      uint32
	AppProgOps      uint32
	AppProgHashes   uint32
	AppProgHashSize string
	AppGlobKeys     uint32
	AppLocalKeys    uint32
	Rekey           bool
	MaxRuntime      time.Duration
	AsyncSending    bool

	// asset spam; make lots of NFT ASAs
	NftAsaPerSecond       uint32 // e.g. 100
	NftAsaPerAccount      uint32 // 0..999
	NftAsaAccountInFlight uint32

	// configuration related to using bootstrapped ledgers built by netgoal
	// TODO: support generatedAssetsCount, generatedApplicationCount
	DeterministicKeys            bool
	GeneratedAccountsCount       uint64
	GeneratedAccountSampleMethod string
	GeneratedAccountsOffset      uint64
	GeneratedAccountsMnemonics   []string

	WeightPayment     float64
	WeightAsset       float64
	WeightApp         float64
	WeightNFTCreation float64
}

// DefaultConfig object for Ping Pong
var DefaultConfig = PpConfig{
	SrcAccount:      "",
	RandomizeFee:    false,
	RandomizeAmt:    false,
	RandomizeDst:    false,
	MaxRandomDst:    200000,
	MaxFee:          10000,
	MinFee:          1000,
	MaxAmt:          1000,
	TxnPerSec:       200,
	NumPartAccounts: 10,
	RunTime:         10 * time.Second,
	RefreshTime:     3600 * time.Second,
	MinAccountFunds: 100000,
	GroupSize:       1,
	NumAsset:        0,
	MinAccountAsset: 10000000,
	NumApp:          0,
	NumBoxUpdate:    0,
	NumBoxRead:      0,
	AppProgOps:      0,
	AppProgHashes:   0,
	AppProgHashSize: "sha256",
	Rekey:           false,
	MaxRuntime:      0,

	ProgramProbability: 1,

	NftAsaAccountInFlight: 5,
	NftAsaPerAccount:      900,
}

// LoadConfigFromFile reads and loads Ping Pong configuration
func LoadConfigFromFile(file string) (cfg PpConfig, err error) {
	cfg = DefaultConfig

	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	err = dec.Decode(&cfg)
	return cfg, err
}

// Save writes configuration to a file
func (cfg PpConfig) Save(file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := codecs.NewFormattedJSONEncoder(f)
	return enc.Encode(cfg)
}

// Dump configuration to output stream
func (cfg PpConfig) Dump(stream io.Writer) {
	enc := codecs.NewFormattedJSONEncoder(stream)
	enc.Encode(cfg)
}

// SetDefaultWeights ensures a reasonable configuration of traffic generation weights.
// With no weights set, and old args about what mode to run, each activated traffic type gets a weight of 1.
// With no weights set and some activated traffic type other than payment, payment gets deactivated (zero weight) to maintain compatibility with prior behavior. WeightPayment must be explicitly set to add it to the mix if other modes are activated.
func (cfg *PpConfig) SetDefaultWeights() {
	const epsilon = 0.0000001
	if cfg.WeightPayment+cfg.WeightAsset+cfg.WeightApp+cfg.WeightNFTCreation < epsilon {
		// set up some sensible run probability weights
		if cfg.NumAsset > 0 && cfg.WeightAsset < epsilon {
			cfg.WeightAsset = 1
		}
		if cfg.NumApp > 0 && cfg.WeightApp < epsilon {
			cfg.WeightApp = 1
		}
		if cfg.NftAsaPerSecond > 0 && cfg.WeightNFTCreation < epsilon {
			cfg.WeightNFTCreation = 1
		}
		if cfg.NumAsset == 0 && cfg.NumApp == 0 && cfg.NftAsaPerSecond == 0 && cfg.WeightPayment < epsilon {
			// backwards compatibility, if a mode is specified we wouldn't run payment traffic, so only set it when no mode is specified
			cfg.WeightPayment = 1
		}
	}
}

var accountSampleMethods = []string{
	"",
	"random",
	"sequential",
	"mnemonic",
}

// Check returns an error if config is invalid.
func (cfg *PpConfig) Check() error {
	sampleOk := false
	for _, v := range accountSampleMethods {
		if v == cfg.GeneratedAccountSampleMethod {
			sampleOk = true
			break
		}
	}
	if !sampleOk {
		return fmt.Errorf("unknown GeneratedAccountSampleMethod: %s", cfg.GeneratedAccountSampleMethod)
	}
	if cfg.DeterministicKeys && (cfg.GeneratedAccountsOffset+uint64(cfg.NumPartAccounts) > cfg.GeneratedAccountsCount) {
		return fmt.Errorf("(GeneratedAccountsOffset %d) + (NumPartAccounts %d) > (GeneratedAccountsCount %d)", cfg.GeneratedAccountsOffset, cfg.NumPartAccounts, cfg.GeneratedAccountsCount)
	}

	return nil
}
