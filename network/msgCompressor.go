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

package network

import (
	"bytes"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/DataDog/zstd"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network/vpack"
	"github.com/algorand/go-algorand/protocol"
)

var zstdCompressionMagic = [4]byte{0x28, 0xb5, 0x2f, 0xfd}

const zstdCompressionLevel = zstd.BestSpeed

// voteCompressionAbortMessage is a single-byte payload sent with a VP tag to signal
// that stateful compression should be disabled for this connection.
// When either encoder or decoder encounters an error, it sends VP+0xFF to notify
// the peer, then both sides disable stateful compression and fall back to AV messages.
const voteCompressionAbortMessage byte = 0xFF

// voteCompressionError wraps errors from stateful vote compression/decompression.
// This error type signals that an abort message should be sent to the peer.
type voteCompressionError struct{ err error }

func (e *voteCompressionError) Error() string { return e.err.Error() }
func (e *voteCompressionError) Unwrap() error { return e.err }

// zstdCompressMsg returns a concatenation of a tag and compressed data
func zstdCompressMsg(tbytes []byte, d []byte) ([]byte, string) {
	bound := max(zstd.CompressBound(len(d)),
		// although CompressBound allocated more than the src size, this is an implementation detail.
		// increase the buffer size to always have enough space for the raw data if compression fails.
		len(d))
	mbytesComp := make([]byte, len(tbytes)+bound)
	copy(mbytesComp, tbytes)
	comp, err := zstd.CompressLevel(mbytesComp[len(tbytes):], d, zstdCompressionLevel)
	if err != nil {
		// fallback and reuse non-compressed original data
		logMsg := fmt.Sprintf("failed to compress into buffer of len %d: %v", len(d), err)
		copied := copy(mbytesComp[len(tbytes):], d)
		return mbytesComp[:len(tbytes)+copied], logMsg
	}
	mbytesComp = mbytesComp[:len(tbytes)+len(comp)]
	return mbytesComp, ""
}

func vpackCompressVote(tbytes []byte, d []byte) ([]byte, string) {
	var enc vpack.StatelessEncoder
	bound := vpack.MaxCompressedVoteSize
	// Pre-allocate buffer for tag bytes and compressed data
	mbytesComp := make([]byte, len(tbytes)+bound)
	copy(mbytesComp, tbytes)
	comp, err := enc.CompressVote(mbytesComp[len(tbytes):], d)
	if err != nil {
		// fallback and reuse non-compressed original data
		logMsg := fmt.Sprintf("failed to compress vote into buffer of len %d: %v", len(d), err)
		copied := copy(mbytesComp[len(tbytes):], d)
		return mbytesComp[:len(tbytes)+copied], logMsg
	}

	result := mbytesComp[:len(tbytes)+len(comp)]
	return result, ""
}

// MaxDecompressedMessageSize defines a maximum decompressed data size
// to prevent zip bombs. This depends on MaxTxnBytesPerBlock consensus parameter
// and should be larger.
const MaxDecompressedMessageSize = 20 * 1024 * 1024 // some large enough value

// wsPeerMsgCodec performs optional message compression/decompression for certain
// types of messages. It handles:
// - zstd compression for PP proposals (outgoing not implemented)
// - stateless vpack compression for AV votes (outgoing not implemented)
// - stateful vpack compression for VP votes (both directions)
type wsPeerMsgCodec struct {
	log    logging.Logger
	origin string

	// decompressors
	ppdec zstdProposalDecompressor
	avdec vpackVoteDecompressor

	// stateful vote compression (if enabled).
	// If either side encounters an error, or if we receive an abort, we disable
	// stateful compression entirely and fall back to stateless AV traffic.
	statefulVoteEnabled   atomic.Bool
	statefulVoteTableSize uint
	statefulVoteEnc       *vpack.StatefulEncoder
	statefulVoteDec       *vpack.StatefulDecoder
}

func (c *wsPeerMsgCodec) switchOffStatefulVoteCompression() {
	c.statefulVoteEnabled.Store(false)
}

type zstdProposalDecompressor struct{}

func (dec zstdProposalDecompressor) accept(data []byte) bool {
	return len(data) > 4 && bytes.Equal(data[:4], zstdCompressionMagic[:])
}

type vpackVoteDecompressor struct {
	enabled bool
	dec     *vpack.StatelessDecoder
}

func (dec vpackVoteDecompressor) convert(data []byte) ([]byte, error) {
	return dec.dec.DecompressVote(nil, data)
}

func (dec zstdProposalDecompressor) convert(data []byte) ([]byte, error) {
	r := zstd.NewReader(bytes.NewReader(data))
	defer r.Close()
	b := make([]byte, 0, 3*len(data))
	for {
		if len(b) == cap(b) {
			// grow capacity, retain length
			b = append(b, 0)[:len(b)]
		}
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			if err == io.EOF {
				return b, nil
			}
			return nil, err
		}
		if len(b) > MaxDecompressedMessageSize {
			return nil, fmt.Errorf("proposal data is too large: %d", len(b))
		}
	}
}

// compress attempts to compress an outgoing message.
// Currently only supports stateful vote compression.
// Returns compressed data and nil error if compression succeeds,
// (nil, nil) if compression is not applicable,
// (nil, vpError) if stateful compression fails (caller should send abort message).
func (c *wsPeerMsgCodec) compress(tag protocol.Tag, data []byte) ([]byte, error) {
	if tag == protocol.AgreementVoteTag && c.statefulVoteEnabled.Load() {
		// Skip the tag bytes (first 2 bytes are the AV tag)
		if len(data) < 2 {
			return nil, nil
		}
		// Input data is AV+stateless-compressed from broadcast
		// We only need to apply stateful compression on top
		statelessCompressed := data[2:]

		// initialize stateful encoder on first use
		if c.statefulVoteEnc == nil {
			enc, err := vpack.NewStatefulEncoder(c.statefulVoteTableSize)
			if err != nil {
				c.log.Warnf("failed to initialize stateful vote encoder for peer %s, disabling: %v", c.origin, err)
				networkVPCompressionErrors.Inc(nil)
				c.switchOffStatefulVoteCompression()
				return nil, &voteCompressionError{err: err}
			}
			c.statefulVoteEnc = enc
			c.log.Debugf("stateful vote encoder initialized for peer %s (table size %d)", c.origin, c.statefulVoteTableSize)
		}

		tagLen := len(protocol.VotePackedTag)
		result := make([]byte, tagLen+vpack.MaxCompressedVoteSize)
		copy(result, protocol.VotePackedTag)
		// apply stateful compression to stateless-compressed data
		compressed, err := c.statefulVoteEnc.Compress(result[tagLen:], statelessCompressed)
		if err != nil {
			c.log.Warnf("stateful vote compression failed for peer %s, disabling: %v", c.origin, err)
			networkVPCompressionErrors.Inc(nil)
			c.switchOffStatefulVoteCompression()
			return nil, &voteCompressionError{err: err}
		}
		finalResult := result[:tagLen+len(compressed)]
		// Track stateful compression layer only: stateless-compressed input → VP output
		networkVPUncompressedBytesSent.AddUint64(uint64(len(statelessCompressed)), nil)
		networkVPCompressedBytesSent.AddUint64(uint64(len(compressed)), nil)
		return finalResult, nil
	}
	return nil, nil
}

// decompress handles incoming message decompression based on tag type
func (c *wsPeerMsgCodec) decompress(tag protocol.Tag, data []byte) ([]byte, error) {
	switch tag {
	case protocol.ProposalPayloadTag:
		// sender might support compressed payload but fail to compress for whatever reason,
		// in this case it sends non-compressed payload - the receiver decompress only if it is compressed.
		if c.ppdec.accept(data) {
			res, err := c.ppdec.convert(data)
			if err != nil {
				return nil, fmt.Errorf("peer %s: %w", c.origin, err)
			}
			return res, nil
		}
		c.log.Warnf("peer %s supported zstd but sent non-compressed data", c.origin)

	case protocol.AgreementVoteTag:
		if c.avdec.enabled {
			res, err := c.avdec.convert(data)
			if err != nil {
				c.log.Warnf("peer %s vote decompress error: %v", c.origin, err)
				// fall back to original data
				return data, nil
			}
			return res, nil
		}

	case protocol.VotePackedTag:
		// Check for abort message first
		if len(data) == 1 && data[0] == voteCompressionAbortMessage {
			c.log.Infof("Received VP abort message from peer %s, disabling stateful encoding", c.origin)
			networkVPAbortMessagesReceived.Inc(nil)
			// Peer signalled stateful compression should stop; disable both encode and decode paths.
			c.switchOffStatefulVoteCompression()
			// Drop this message silently (it's just a control signal)
			return nil, nil
		}

		if !c.statefulVoteEnabled.Load() {
			c.log.Debugf("dropping VP message from %s: stateful decompression disabled", c.origin)
			return nil, nil
		}
		if c.statefulVoteDec == nil {
			dec, err := vpack.NewStatefulDecoder(c.statefulVoteTableSize)
			if err != nil {
				c.log.Warnf("failed to initialize stateful vote decoder for peer %s, disabling: %v", c.origin, err)
				networkVPDecompressionErrors.Inc(nil)
				c.switchOffStatefulVoteCompression()
				return nil, &voteCompressionError{err: err}
			}
			c.statefulVoteDec = dec
			c.log.Debugf("stateful vote decoder initialized for peer %s (table size %d)", c.origin, c.statefulVoteTableSize)
		}
		// StatefulDecoder decompresses to "stateless-compressed" format
		statelessCompressed, err := c.statefulVoteDec.Decompress(make([]byte, 0, vpack.MaxCompressedVoteSize), data)
		if err != nil {
			c.log.Warnf("stateful vote decompression failed for peer %s, disabling: %v", c.origin, err)
			networkVPDecompressionErrors.Inc(nil)
			c.switchOffStatefulVoteCompression()
			return nil, &voteCompressionError{err: err}
		}

		var statelessDec vpack.StatelessDecoder
		voteBody, err := statelessDec.DecompressVote(make([]byte, 0, vpack.MaxMsgpackVoteSize), statelessCompressed)
		if err != nil {
			c.log.Warnf("stateless vote decompression failed after stateful for peer %s, disabling: %v", c.origin, err)
			networkVPDecompressionErrors.Inc(nil)
			c.switchOffStatefulVoteCompression()
			return nil, &voteCompressionError{err: err}
		}

		return voteBody, nil
	}

	return data, nil
}

func makeWsPeerMsgCodec(wp *wsPeer) *wsPeerMsgCodec {
	c := wsPeerMsgCodec{
		log:    wp.log,
		origin: wp.originAddress,
	}

	c.ppdec = zstdProposalDecompressor{}
	// have both ends advertised support for compression?
	if wp.enableVoteCompression && wp.vpackVoteCompressionSupported() {
		c.avdec = vpackVoteDecompressor{
			enabled: true,
			dec:     vpack.NewStatelessDecoder(),
		}
	}

	// Initialize stateful compression negotiation details if both nodes support it
	// Stateful compression requires stateless compression to be available since VP messages
	// decompress in two stages: VP → stateless-compressed → raw vote
	if wp.enableVoteCompression && // this node's configuration allows vote compression
		wp.voteCompressionTableSize > 0 && // this node's configuration allows stateful vote compression
		wp.vpackVoteCompressionSupported() && // the other side has advertised vote compression
		wp.vpackStatefulCompressionSupported() { // the other side has advertised stateful vote compression
		tableSize := wp.getBestVpackTableSize()
		if tableSize > 0 {
			c.statefulVoteEnabled.Store(true)
			c.statefulVoteTableSize = tableSize
			wp.log.Debugf("Stateful compression negotiated with table size %d (our max: %d)", tableSize, wp.voteCompressionTableSize)
		}
	}

	return &c
}
