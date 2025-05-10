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
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/rpcs"
)

const downtimeLimit time.Duration = 5 * time.Minute

type blockstats struct {
	log           EventSender
	lastBlock     uint64
	lastBlockTime time.Time
}

func (stats *blockstats) init(block basics.Round) {
}

func (stats *blockstats) onBlock(block rpcs.EncodedBlockCert) {
	now := time.Now()
	blockHeader := block.Block.BlockHeader

	// Ensure we only create stats from consecutive blocks.
	if stats.lastBlock+1 != uint64(blockHeader.Round) {
		stats.lastBlock = uint64(blockHeader.Round)
		stats.lastBlockTime = now
		return
	}

	// Grab unique users.
	users := make(map[string]bool)
	for _, tx := range block.Block.Payset {
		users[tx.Txn.Sender.String()] = true
	}

	duration := now.Sub(stats.lastBlockTime)
	downtime := 0 * time.Second
	if duration > downtimeLimit {
		downtime = duration - downtimeLimit
	}

	stats.log.EventWithDetails(telemetryspec.Agreement, telemetryspec.BlockStatsEvent, telemetryspec.BlockStatsEventDetails{
		Hash:                block.Block.Hash().String(),
		OriginalProposer:    block.Certificate.Proposal.OriginalProposer.String(),
		Round:               uint64(blockHeader.Round),
		Transactions:        uint64(len(block.Block.Payset)),
		ActiveUsers:         uint64(len(users)),
		AgreementDurationMs: uint64(duration.Nanoseconds() / 1000 / 1000),
		NetworkDowntimeMs:   uint64(downtime.Nanoseconds() / 1000 / 1000),
	})

	stats.lastBlock = uint64(blockHeader.Round)
	stats.lastBlockTime = now
}
