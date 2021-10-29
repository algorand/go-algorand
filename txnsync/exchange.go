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

package txnsync

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

const txnBlockMessageVersion = 1
const maxAcceptedMsgSeq = 64

// set in init() in service.go
var maxBloomFilterSize int
var maxEncodedTransactionGroupBytes int

const maxProposalSize = 3500000 // 10K * 32 + sizeof(block header)

type transactionBlockMessage struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	Version              int32                   `codec:"v"`
	Round                basics.Round            `codec:"r"`
	TxnBloomFilter       encodedBloomFilter      `codec:"b"`
	UpdatedRequestParams requestParams           `codec:"p"`
	TransactionGroups    packedTransactionGroups `codec:"g"`
	MsgSync              timingParams            `codec:"t"`
	RelayedProposal      relayedProposal         `codec:"rp"`
}

type encodedBloomFilter struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	BloomFilterType byte          `codec:"t"`
	EncodingParams  requestParams `codec:"p"`
	BloomFilter     []byte        `codec:"f,allocbound=maxBloomFilterSize"`
	ClearPrevious   byte          `codec:"c"`
}

type requestParams struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	Offset    byte `codec:"o"`
	Modulator byte `codec:"m"`
}

const (
	compressionFormatNone byte = iota
	compressionFormatDeflate
)

type packedTransactionGroups struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	Bytes                []byte `codec:"g,allocbound=maxEncodedTransactionGroupBytes"`
	CompressionFormat    byte   `codec:"c"`
	LenDecompressedBytes uint64 `codec:"l"`
}

type timingParams struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	RefTxnBlockMsgSeq   uint64   `codec:"s"`
	ResponseElapsedTime uint64   `codec:"r"`
	AcceptedMsgSeq      []uint64 `codec:"a,allocbound=maxAcceptedMsgSeq"`
	NextMsgMinDelay     uint64   `codec:"m"`
}

const (
	noProposal              byte = iota //nolint:deadcode,unused,varcheck
	transactionsForProposal             //nolint:deadcode,unused,varcheck
)

type relayedProposal struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	RawBytes        []byte        `codec:"b,allocbound=maxProposalSize"`
	ExcludeProposal crypto.Digest `codec:"e"`
	Content         byte          `codec:"c"`
}
