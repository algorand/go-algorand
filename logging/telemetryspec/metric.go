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

package telemetryspec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Telemetry metrics

// Metric is the type used to identify metrics
// We want these to be stable and easy to find / document so we can create queries against them.
type Metric string

// MetricDetails is an interface to be implemented by structs containing metrics for a specific identifier.
// The identifier is queried directly from the MetricDetails to simplify things.
type MetricDetails interface {
	Identifier() Metric
}

//-------------------------------------------------------
// AssembleBlock

// AssembleBlockStats is the set of stats captured when we compute AssemblePayset
type AssembleBlockStats struct {
	StartCount                int
	IncludedCount             int // number of transactions that are included in a block
	InvalidCount              int // number of transaction groups that are included in a block
	MinFeeErrorCount          int // number of transactions excluded because the fee is too low
	ExpiredCount              int // number of transactions removed because of expiration
	ExpiredLongLivedCount     int // number of expired transactions with non-super short LastValid values
	LeaseErrorCount           int // number of transactions removed because it has an already used lease
	MinFee                    uint64
	MaxFee                    uint64
	AverageFee                uint64
	MinLength                 int
	MaxLength                 int
	MinPriority               uint64
	MaxPriority               uint64
	CommittedCount            int // number of transaction blocks that are included in a block
	StopReason                string
	TotalLength               uint64
	EarlyCommittedCount       uint64 // number of transaction groups that were pending on the transaction pool but have been included in previous block
	Nanoseconds               int64
	ProcessingTime            transactionProcessingTimeDistribution
	BlockGenerationDuration   uint64
	TransactionsLoopStartTime int64
	StateProofNextRound       uint64 // next round for which state proof if expected
	StateProofStats           StateProofStats
}

// StateProofStats is the set of stats captured when a StateProof is present in the assembled block
type StateProofStats struct {
	ProvenWeight   uint64
	SignedWeight   uint64
	NumReveals     int
	NumPosToReveal int
	TxnSize        int
}

// AssembleBlockTimeout represents AssembleBlock exiting due to timeout
const AssembleBlockTimeout = "timeout"

// AssembleBlockTimeoutEmpty represents AssembleBlock giving up after a timeout and returning an empty block
const AssembleBlockTimeoutEmpty = "timeout-empty"

// AssembleBlockFull represents AssembleBlock exiting due to block being full
const AssembleBlockFull = "block-full"

// AssembleBlockEmpty represents AssembleBlock exiting due to no more txns
const AssembleBlockEmpty = "pool-empty"

// AssembleBlockPoolBehind represents the transaction pool being more than two roudns behind
const AssembleBlockPoolBehind = "pool-behind"

// AssembleBlockEvalOld represents the assembled block that was returned being a round too old
const AssembleBlockEvalOld = "eval-old"

// AssembleBlockAbandon represents the block generation being abandoned since it won't be needed.
const AssembleBlockAbandon = "block-abandon"

const assembleBlockMetricsIdentifier Metric = "AssembleBlock"

// AssembleBlockMetrics is the set of metrics captured when we compute AssembleBlock
type AssembleBlockMetrics struct {
	AssembleBlockStats
}

// Identifier implements the required MetricDetails interface, retrieving the Identifier for this set of metrics.
func (m AssembleBlockMetrics) Identifier() Metric {
	return assembleBlockMetricsIdentifier
}
func (m AssembleBlockStats) String() string {
	b := &bytes.Buffer{}
	b.WriteString(fmt.Sprintf("StartCount:%d, ", m.StartCount))
	b.WriteString(fmt.Sprintf("IncludedCount:%d, ", m.IncludedCount))
	b.WriteString(fmt.Sprintf("InvalidCount:%d, ", m.InvalidCount))
	b.WriteString(fmt.Sprintf("MinFeeErrorCount:%d, ", m.MinFeeErrorCount))
	b.WriteString(fmt.Sprintf("ExpiredCount:%d, ", m.ExpiredCount))
	b.WriteString(fmt.Sprintf("ExpiredLongLivedCount:%d, ", m.ExpiredLongLivedCount))
	b.WriteString(fmt.Sprintf("LeaseErrorCount:%d, ", m.LeaseErrorCount))
	b.WriteString(fmt.Sprintf("MinFee:%d, ", m.MinFee))
	b.WriteString(fmt.Sprintf("MaxFee:%d, ", m.MaxFee))
	b.WriteString(fmt.Sprintf("AverageFee:%d, ", m.AverageFee))
	b.WriteString(fmt.Sprintf("MinLength:%d, ", m.MinLength))
	b.WriteString(fmt.Sprintf("MaxLength:%d, ", m.MaxLength))
	b.WriteString(fmt.Sprintf("MinPriority:%d, ", m.MinPriority))
	b.WriteString(fmt.Sprintf("MaxPriority:%d, ", m.MaxPriority))
	b.WriteString(fmt.Sprintf("CommittedCount:%d, ", m.CommittedCount))
	b.WriteString(fmt.Sprintf("StopReason:%s, ", m.StopReason))
	b.WriteString(fmt.Sprintf("TotalLength:%d, ", m.TotalLength))
	b.WriteString(fmt.Sprintf("EarlyCommittedCount:%d, ", m.EarlyCommittedCount))
	b.WriteString(fmt.Sprintf("Nanoseconds:%d, ", m.Nanoseconds))
	b.WriteString(fmt.Sprintf("ProcessingTime:%v, ", m.ProcessingTime))
	b.WriteString(fmt.Sprintf("BlockGenerationDuration:%d, ", m.BlockGenerationDuration))
	b.WriteString(fmt.Sprintf("TransactionsLoopStartTime:%d, ", m.TransactionsLoopStartTime))
	b.WriteString(fmt.Sprintf("StateProofNextRound:%d, ", m.StateProofNextRound))
	emptySPStats := StateProofStats{}
	if m.StateProofStats != emptySPStats {
		b.WriteString(fmt.Sprintf("ProvenWeight:%d, ", m.StateProofStats.ProvenWeight))
		b.WriteString(fmt.Sprintf("SignedWeight:%d, ", m.StateProofStats.SignedWeight))
		b.WriteString(fmt.Sprintf("NumReveals:%d, ", m.StateProofStats.NumReveals))
		b.WriteString(fmt.Sprintf("NumPosToReveal:%d, ", m.StateProofStats.NumPosToReveal))
		b.WriteString(fmt.Sprintf("TxnSize:%d", m.StateProofStats.TxnSize))
	}
	return b.String()
}

//-------------------------------------------------------
// ProcessBlock

const processBlockMetricsIdentifier Metric = "ProcessBlock"

// ProcessBlockMetrics is the set of metrics captured when we process OnNewBlock
type ProcessBlockMetrics struct {
	KnownCommittedCount   uint
	UnknownCommittedCount uint
	ExpiredCount          uint
	RemovedInvalidCount   uint
}

// Identifier implements the required MetricDetails interface, retrieving the Identifier for this set of metrics.
func (m ProcessBlockMetrics) Identifier() Metric {
	return processBlockMetricsIdentifier
}

//-------------------------------------------------------
// RoundTiming

const roundTimingMetricsIdentifier Metric = "RoundTiming"

// RoundTimingMetrics contain timing details for common message types.
// All times (except round start time) are offset times, in int64 ns
// precision relative to RoundTimingMetrics.LRoundStart.
type RoundTimingMetrics struct {
	// We keep track of timingInfo for period 0 step <= 3 only, for brevity
	Round          uint64 `json:"round"`
	ConcludingStep uint64 `json:"laststep"`

	// Local Timings. Eventually, we could
	// attach timing information at the network layer to messages - but that is a
	// larger change I'd rather avoid for now. However, this means right now we
	// can only recover transit time information through telemetry, so we'll save
	// logging more thorough delivery distributions for a second pass. (-ben)
	LRoundStart time.Time `json:"lroundstart"`

	// LVotes contains times this player (would have) sent corresponding votes,
	// and times this player receives votes.
	LVotes map[uint64]LocalMsgTiming `json:"lvotes"`

	// LPayload contains times this player received payloads relevant to this round.
	LPayload LocalMsgTiming `json:"lpayload"`

	// BlockAssemble time specifies the duration from start of Round to Block Assembly completion
	BlockAssemble time.Duration `json:"lblockassemble"`

	// Payload Validation time contains the event times for Payload validation, once for each account
	PayloadValidation LocalMsgTiming `json:"lpayloadvalidation"`
}

// Identifier implements the required MetricDetails interface, retrieving the Identifier for this set of metrics.
func (m RoundTimingMetrics) Identifier() Metric {
	return roundTimingMetricsIdentifier
}

// -------------------------------------------------------
// AccountsUpdate
const accountsUpdateMetricsIdentifier Metric = "AccountsUpdate"

// AccountsUpdateMetrics is the set of metrics captured when we process accountUpdates.commitRound
type AccountsUpdateMetrics struct {
	StartRound                uint64
	RoundsCount               uint64
	OldAccountPreloadDuration time.Duration
	MerkleTrieUpdateDuration  time.Duration
	AccountsWritingDuration   time.Duration
	DatabaseCommitDuration    time.Duration
	MemoryUpdatesDuration     time.Duration
	UpdatedAccountsCount      uint64
	UpdatedResourcesCount     uint64
	UpdatedCreatablesCount    uint64
}

// Identifier implements the required MetricDetails interface, retrieving the Identifier for this set of metrics.
func (m AccountsUpdateMetrics) Identifier() Metric {
	return accountsUpdateMetricsIdentifier
}

type transactionProcessingTimeDistribution struct {
	// 10 buckets: 0-100Kns, 100Kns-200Kns .. 900Kns-1ms
	// 9 buckets: 1ms-2ms .. 9ms-10ms
	// 9 buckets: 10ms-20ms .. 90ms-100ms
	// 9 buckets: 100ms-200ms .. 900ms-1s
	// 1 bucket: 1s+
	transactionBuckets [38]int
}

// MarshalJSON supports json.Marshaler interface
// generate comma delimited text representing the transaction processing timing
func (t transactionProcessingTimeDistribution) MarshalJSON() ([]byte, error) {
	var outStr strings.Builder
	outStr.WriteString("[")
	for i, bucket := range t.transactionBuckets {
		outStr.WriteString(strconv.Itoa(bucket))
		if i != len(t.transactionBuckets)-1 {
			outStr.WriteString(",")
		}
	}
	outStr.WriteString("]")
	return []byte(outStr.String()), nil
}

func (t *transactionProcessingTimeDistribution) AddTransaction(duration time.Duration) {
	var idx int64
	if duration < 10*time.Millisecond {
		if duration < time.Millisecond {
			idx = int64(duration / (100000 * time.Nanosecond))
		} else {
			idx = int64(10 + duration/(1*time.Millisecond))
		}
	} else {
		if duration < 100*time.Millisecond {
			idx = int64(19 + duration/(10*time.Millisecond))
		} else if duration < time.Second {
			idx = int64(28 + duration/(100*time.Millisecond))
		} else {
			idx = 37
		}
	}
	if idx >= 0 && idx <= 37 {
		t.transactionBuckets[idx]++
	}
}

func (t *transactionProcessingTimeDistribution) UnmarshalJSON(data []byte) error {
	var arr []json.Number
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	if len(arr) != len(t.transactionBuckets) {
		return fmt.Errorf("array has %d buckets, should have %d", len(arr), len(t.transactionBuckets))
	}
	for i := range t.transactionBuckets {
		val, err := arr[i].Int64()
		if err != nil {
			return fmt.Errorf("bucket has invalid value %s", arr[i])
		}
		t.transactionBuckets[i] = int(val)
	}
	return nil
}

func (t *transactionProcessingTimeDistribution) MarshalString() string {
	var out strings.Builder
	var offset int
	var base, mul time.Duration
bucketloop:
	for i, val := range t.transactionBuckets {
		switch {
		case i < 10:
			mul = 100000 * time.Nanosecond
		case i < 19:
			mul = time.Millisecond
			base = mul
			offset = 10
		case i < 28:
			mul = 10 * time.Millisecond
			base = mul
			offset = 19
		case i < 37:
			mul = 100 * time.Millisecond
			base = mul
			offset = 28
		case i == 37:
			break bucketloop
		}
		start := base + time.Duration(i-offset)*mul
		end := base + time.Duration(i+1-offset)*mul
		out.WriteString(fmt.Sprintf("%s - %s: %d\n", start, end, val))
	}
	out.WriteString(fmt.Sprintf(">1s: %d\n", t.transactionBuckets[37]))
	return out.String()
}
