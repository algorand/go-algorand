// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package agreement

import (
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// Agreement reads only the start of a proposal payload when it arrives, up to
// the payset. It hashes and decodes the payload once the proposalStore is
// waiting for a payload with that encoding. See decodeProposal and
// player.decodePayloadIfWanted.

// payloadPrefixLimit bounds how much of a payload is read before agreement
// decides whether it wants it. Every field that decision needs comes before
// the payset in a canonical encoding, and together they take a few kilobytes.
const payloadPrefixLimit = 64 * 1024

// payloadPrefix holds the fields of a transmittedPayload that decide whether
// agreement wants it.
type payloadPrefix struct {
	round            basics.Round
	originalPeriod   period
	originalProposer basics.Address
	priorVote        unauthenticatedVote

	// numEntries is the number of entries the payload's map header
	// declares, and entriesStartIdx is the offset of the first entry.
	numEntries      uint32
	entriesStartIdx int
	// voteStartIdx and voteEndIdx are the offsets of the "pv" entry, key and
	// value. Both are zero if the prefix has none.
	voteStartIdx, voteEndIdx int
}

// parsePayloadPrefix reads the fields of payloadPrefix from the first
// payloadPrefixLimit bytes of encodedTransmittedPayload. It returns
// msgp.ErrShortBytes if those bytes end before it is done.
//
// It stops at the payset or at the first key that sorts after it. A canonical
// encoding writes its keys in sorted order, and all of these fields sort
// before the payset, so a field not read by then is zero in a canonical
// encoding and is left zero here. decodeDeferredPayload refuses a payload
// whose decoded fields differ from the result.
func parsePayloadPrefix(encodedTransmittedPayload []byte) (payloadPrefix, error) {
	prefix := encodedTransmittedPayload[:min(len(encodedTransmittedPayload), payloadPrefixLimit)]
	var pp payloadPrefix
	st := msgp.DefaultUnmarshalState
	if st.AllowableDepth == 0 {
		return pp, msgp.ErrMaxDepthExceeded{}
	}
	st.AllowableDepth--

	n, _, b, err := msgp.ReadMapHeaderBytes(prefix)
	if err != nil {
		return pp, err
	}
	pp.numEntries = uint32(n)
	pp.entriesStartIdx = len(prefix) - len(b)
	for range n {
		start := len(prefix) - len(b)
		var key []byte
		key, b, err = msgp.ReadMapKeyZC(b)
		if err != nil {
			return pp, err
		}
		if string(key) >= "txns" {
			break
		}
		switch string(key) {
		case "rnd":
			b, err = pp.round.UnmarshalMsgWithState(b, st)
		case "oper":
			b, err = pp.originalPeriod.UnmarshalMsgWithState(b, st)
		case "oprop":
			b, err = pp.originalProposer.UnmarshalMsgWithState(b, st)
		case "pv":
			if pp.voteEndIdx != 0 {
				return pp, errors.New("payload: repeated prior vote")
			}
			b, err = pp.priorVote.UnmarshalMsgWithState(b, st)
			pp.voteStartIdx, pp.voteEndIdx = start, len(prefix)-len(b)
		default:
			b, err = skipWithDepth(b, st.AllowableDepth)
		}
		if err != nil {
			return pp, fmt.Errorf("payload prefix: field %q: %w", key, err)
		}
	}
	return pp, nil
}

// writeProposalEncoding writes to w the encoding of the unauthenticatedProposal
// in encodedTransmittedPayload, a PP message, without decoding it.
//
// An encoded transmittedPayload holds the proposal's fields and the prior vote
// ("pv") in one map. The proposal's encoding is the same bytes without the
// "pv" entry, with the map header counting one entry fewer.
//
// The output is what protocol.Encode gives for the decoded proposal when
// encodedTransmittedPayload is canonically encoded, as nodes send it.
// Otherwise it generally differs.
func writeProposalEncoding(w io.Writer, encodedTransmittedPayload []byte) error {
	pp, err := parsePayloadPrefix(encodedTransmittedPayload)
	if err != nil {
		return err
	}
	parts := [][]byte{encodedTransmittedPayload}
	if pp.voteEndIdx != 0 {
		parts = [][]byte{
			msgp.AppendMapHeader(nil, pp.numEntries-1),
			encodedTransmittedPayload[pp.entriesStartIdx:pp.voteStartIdx],
			encodedTransmittedPayload[pp.voteEndIdx:],
		}
	}
	for _, part := range parts {
		if _, err := w.Write(part); err != nil {
			return err
		}
	}
	return nil
}

// payloadEncodingDigest computes proposalValue.EncodingDigest from a PP
// message without decoding it: the hash that crypto.HashObj gives for the
// decoded unauthenticatedProposal. A payload that is not canonically encoded
// generally gets another digest, and then matches no proposal-value.
func payloadEncodingDigest(encodedTransmittedPayload []byte) (crypto.Digest, error) {
	h := crypto.NewHash()
	h.Write([]byte(protocol.Payload))
	if err := writeProposalEncoding(h, encodedTransmittedPayload); err != nil {
		return crypto.Digest{}, err
	}
	var d crypto.Digest
	h.Sum(d[:0])
	return d, nil
}

// decodeDeferredPayload decodes the payload deferred holds, if its
// EncodingDigest is one of wantedEncodingDigests, and fails otherwise without
// decoding its payset.
//
// The digest it matched is of the bytes received, so it is not kept for
// unauthenticatedProposal.value, which hashes the canonical encoding.
func decodeDeferredPayload(deferred unauthenticatedProposal, wantedEncodingDigests []crypto.Digest) (unauthenticatedProposal, error) {
	data := deferred.deferredPayload
	digest, err := payloadEncodingDigest(data)
	if err != nil {
		return unauthenticatedProposal{}, err
	}
	if !slices.Contains(wantedEncodingDigests, digest) {
		return unauthenticatedProposal{}, errors.New("proposalStore: payload encoding matches no proposal-value waiting for a payload")
	}

	var tp transmittedPayload
	if err := protocol.Decode(data, &tp); err != nil {
		return unauthenticatedProposal{}, err
	}
	up := tp.unauthenticatedProposal
	// The decoded fields must be the ones agreement read from the prefix.
	if up.Round() != deferred.Round() || up.OriginalPeriod != deferred.OriginalPeriod || up.OriginalProposer != deferred.OriginalProposer {
		return unauthenticatedProposal{}, errors.New("payload fields differ from its prefix")
	}
	if proposalCarriesInvalidTxn(up) {
		return unauthenticatedProposal{}, errors.New("proposal payload carries a malformed transaction")
	}
	up.receivedAt = deferred.receivedAt
	return up, nil
}

// skipWithDepth returns b without its first msgpack object. It accepts
// exactly the input msgp.Skip accepts, except that it returns
// msgp.ErrMaxDepthExceeded if maps and arrays nest more than maxDepth deep.
// It keeps the open maps and arrays in a slice instead of recursing.
func skipWithDepth(b []byte, maxDepth uint64) ([]byte, error) {
	// the number of objects still to skip in each open map or array,
	// innermost last; a map entry counts as two objects
	open := make([]uint64, 0, 16)
	for {
		var err error
		switch t := msgp.NextType(b); t {
		case msgp.MapType, msgp.ArrayType:
			if uint64(len(open)) >= maxDepth {
				return b, msgp.ErrMaxDepthExceeded{}
			}
			var sz int
			var items uint64
			if t == msgp.MapType {
				sz, _, b, err = msgp.ReadMapHeaderBytes(b)
				items = 2 * uint64(sz)
			} else {
				sz, _, b, err = msgp.ReadArrayHeaderBytes(b)
				items = uint64(sz)
			}
			if err != nil {
				return b, err
			}
			if items > 0 {
				open = append(open, items)
				continue
			}
		default:
			// msgp.Skip only recurses into maps and arrays
			b, err = msgp.Skip(b)
			if err != nil {
				return b, err
			}
		}
		// A whole object was skipped: count it against the innermost open
		// map or array, and close each one that it completes.
		for len(open) > 0 {
			open[len(open)-1]--
			if open[len(open)-1] > 0 {
				break
			}
			open = open[:len(open)-1]
		}
		if len(open) == 0 {
			return b, nil
		}
	}
}
