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

package network

import (
	"bytes"
	"fmt"
	"io"

	"github.com/DataDog/zstd"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var zstdCompressionMagic = [4]byte{0x28, 0xb5, 0x2f, 0xfd}

const zstdCompressionLevel = zstd.BestSpeed

// zstdCompressMsg returns a concatenation of a tag and compressed data
func zstdCompressMsg(tbytes []byte, d []byte) ([]byte, string) {
	bound := zstd.CompressBound(len(d))
	if bound < len(d) {
		// although CompressBound allocated more than the src size, this is an implementation detail.
		// increase the buffer size to always have enough space for the raw data if compression fails.
		bound = len(d)
	}
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

// MaxDecompressedMessageSize defines a maximum decompressed data size
// to prevent zip bombs. This depends on MaxTxnBytesPerBlock consensus parameter
// and should be larger.
const MaxDecompressedMessageSize = 20 * 1024 * 1024 // some large enough value

// wsPeerMsgDataConverter performs optional incoming messages conversion.
// At the moment it only supports zstd decompression for payload proposal
type wsPeerMsgDataConverter struct {
	log    logging.Logger
	origin string

	// actual converter(s)
	ppdec zstdProposalDecompressor
}

type zstdProposalDecompressor struct{}

func (dec zstdProposalDecompressor) accept(data []byte) bool {
	return len(data) > 4 && bytes.Equal(data[:4], zstdCompressionMagic[:])
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

func (c *wsPeerMsgDataConverter) convert(tag protocol.Tag, data []byte) ([]byte, error) {
	if tag == protocol.ProposalPayloadTag {
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
	}
	return data, nil
}

func makeWsPeerMsgDataConverter(wp *wsPeer) *wsPeerMsgDataConverter {
	c := wsPeerMsgDataConverter{
		log:    wp.log,
		origin: wp.originAddress,
	}

	c.ppdec = zstdProposalDecompressor{}
	return &c
}
