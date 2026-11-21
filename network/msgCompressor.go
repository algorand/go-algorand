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

package network

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
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

// zstdCompressMsg returns a concatenation of a tag and compressed data,
// or of a tag and d when compressing d fails or does not make it shorter.
func zstdCompressMsg(tbytes []byte, d []byte) ([]byte, string) {
	// zstd.CompressLevel compresses into the buffer it is given only if the
	// buffer holds CompressBound(len(d)) bytes, and allocates one otherwise.
	bound := max(zstd.CompressBound(len(d)),
		// CompressBound(len(d)) is at least len(d). The max keeps room for d
		// in the fallback below even if that changed.
		len(d))
	mbytesComp := make([]byte, len(tbytes)+bound)
	copy(mbytesComp, tbytes)
	comp, err := zstd.CompressLevel(mbytesComp[len(tbytes):], d, zstdCompressionLevel)
	if err != nil || len(comp) >= len(d) {
		// Send d as it is, which receivers also accept. A zstd frame of
		// incompressible data is longer than the data, and wsPeer.readLoop
		// applies Tag.MaxMessageSize to the bytes as sent.
		var logMsg string
		if err != nil {
			logMsg = fmt.Sprintf("failed to compress into buffer of len %d: %v", len(d), err)
		}
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
		// No compressed form: the caller then sends the original message, which
		// it already holds, to every peer. mbytesComp is sized for a compressed
		// vote and cannot hold an uncompressed one.
		logMsg := fmt.Sprintf("failed to compress vote into buffer of len %d: %v", len(d), err)
		return nil, logMsg
	}

	result := mbytesComp[:len(tbytes)+len(comp)]
	return result, ""
}

// MaxDecompressedMessageSize defines a maximum decompressed data size
// to prevent zip bombs. This depends on MaxTxnBytesPerBlock consensus parameter
// and should be larger.
const MaxDecompressedMessageSize = protocol.ProposalPayloadTagMaxSize

// proposalInflateBufs holds buffers of MaxDecompressedMessageSize bytes for
// DecompressProposal to inflate into.
var proposalInflateBufs = sync.Pool{
	New: func() any {
		buf := make([]byte, MaxDecompressedMessageSize)
		return &buf
	},
}

// DecompressProposal decompresses data, the body of a PP message, if it
// starts with the zstd magic, as zstdCompressMsg sends it. Otherwise it
// returns data unchanged. It fails if the decompressed payload is larger than
// MaxDecompressedMessageSize.
func DecompressProposal(data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, zstdCompressionMagic[:]) {
		return data, nil
	}
	// The size of the content is not known until it is inflated, so inflate
	// into a buffer of the largest size allowed and copy the content out.
	bufp := proposalInflateBufs.Get().(*[]byte)
	defer proposalInflateBufs.Put(bufp)
	n, err := zstd.DecompressInto(*bufp, data)
	if err != nil {
		return nil, fmt.Errorf("decompressing proposal: %w", err)
	}
	return bytes.Clone((*bufp)[:n]), nil
}

// wsPeerMsgCodec performs optional message compression/decompression for certain
// types of messages. It handles:
// - stateless vpack compression for AV votes (outgoing not implemented)
// - stateful vpack compression for VP votes (both directions)
//
// PP proposals are compressed by the broadcaster (zstdCompressMsg) but not
// decompressed here. The handler of PP messages calls DecompressProposal for
// the messages it processes.
type wsPeerMsgCodec struct {
	log    logging.Logger
	origin string

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

type vpackVoteDecompressor struct {
	enabled bool
	dec     *vpack.StatelessDecoder
}

func (dec vpackVoteDecompressor) convert(data []byte) ([]byte, error) {
	return dec.dec.DecompressVote(nil, data)
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
		// innerBroadcast sends the original msgpack vote when stateless
		// compression fails. The stateful encoder accepts only stateless
		// output, so send such a vote as it is. Failing here would switch
		// stateful compression off for this peer, and decompress would then
		// drop the VP messages already in flight from it.
		if vpack.IsLikelyUncompressedMsgpack(statelessCompressed) {
			return nil, nil
		}

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
	case protocol.AgreementVoteTag:
		if c.avdec.enabled {
			res, err := c.avdec.convert(data)
			if err != nil {
				if errors.Is(err, vpack.ErrLikelyUncompressed) {
					// allow uncompressed AV to pass through without logging an error
				} else {
					c.log.Warnf("peer %s vote decompress error: %v", c.origin, err)
				}
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
