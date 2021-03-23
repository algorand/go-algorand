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

package pingpong

import (
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/algorand/go-algorand/util/codecs"
)

// ConfigFilename name of configuration file
const ConfigFilename = "ppconfig.json"

// PpConfig defines configuration structure for
type PpConfig struct {
	SrcAccount      string
	DelayBetweenTxn time.Duration
	RandomizeFee    bool
	RandomizeAmt    bool
	RandomizeDst    bool
	MaxFee          uint64
	MinFee          uint64
	MaxAmt          uint64
	TxnPerSec       uint64
	NumPartAccounts uint32
	RunTime         time.Duration
	RestTime        time.Duration
	RefreshTime     time.Duration
	MinAccountFunds uint64
	Quiet           bool
	RandomNote      bool
	RandomLease     bool
	Program         []byte
	LogicArgs       [][]byte
	GroupSize       uint32
	NumAsset        uint32
	MinAccountAsset uint64
	NumApp          uint32
	NumAppOptIn     uint32
	AppProgOps      uint32
	AppProgHashes   uint32
	AppProgHashSize string
	AppGlobKeys     uint32
	AppLocalKeys    uint32
	Rekey           bool
	MaxRuntime      time.Duration

	// asset spam; make lots of NFT ASAs
	NftAsaPerSecond       uint32 // e.g. 100
	NftAsaPerAccount      uint32 // 0..999
	NftAsaAccountInFlight uint32
}

// DefaultConfig object for Ping Pong
var DefaultConfig = PpConfig{
	SrcAccount:      "",
	DelayBetweenTxn: 100,
	RandomizeFee:    false,
	RandomizeAmt:    false,
	RandomizeDst:    false,
	MaxFee:          10000,
	MinFee:          1000,
	MaxAmt:          1000,
	TxnPerSec:       200,
	NumPartAccounts: 10,
	RunTime:         10 * time.Second,
	RestTime:        1 * time.Hour, // Long default rest to avoid accidental DoS
	RefreshTime:     10 * time.Second,
	MinAccountFunds: 100000,
	GroupSize:       1,
	NumAsset:        0,
	MinAccountAsset: 10000000,
	NumApp:          0,
	AppProgOps:      0,
	AppProgHashes:   0,
	AppProgHashSize: "sha256",
	Rekey:           false,
	MaxRuntime:      0,

	NftAsaAccountInFlight: 5,
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
