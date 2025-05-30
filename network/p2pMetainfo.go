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
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/http"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/libp2p/go-libp2p/core/peer"
)

// peerMetaHeaders holds peer metadata headers similar to wsnet http.Header
// due to msgp allocbound enforcement we need to limit the number of headers and values
// but it is cannot be done without msgp modification to accept both map and slice allocbound
// so that introduce a service peerMetaValues type to have allocbound set and msgp generator satisfied.

const maxHeaderKeys = 64
const maxHeaderValues = 16

// SortString is a type that implements sort.Interface for sorting strings
type SortString = basics.SortString

//msgp:allocbound peerMetaValues maxHeaderValues
type peerMetaValues []string

//msgp:allocbound peerMetaHeaders maxHeaderKeys
type peerMetaHeaders map[string]peerMetaValues

func peerMetaHeadersToHTTPHeaders(headers peerMetaHeaders) http.Header {
	httpHeaders := make(http.Header, len(headers))
	for k, v := range headers {
		httpHeaders[k] = v
	}
	return httpHeaders
}

func peerMetaHeadersFromHTTPHeaders(headers http.Header) peerMetaHeaders {
	pmh := make(peerMetaHeaders, len(headers))
	for k, v := range headers {
		pmh[k] = v
	}
	return pmh
}

type peerMetaInfo struct {
	telemetryID  string
	instanceName string
	version      string
	features     string
}

func readPeerMetaHeaders(stream io.ReadWriter, p2pPeer peer.ID, netProtoSupportedVersions []string) (peerMetaInfo, error) {
	var msgLenBytes [2]byte
	rn, err := stream.Read(msgLenBytes[:])
	if rn != 2 || err != nil {
		err0 := fmt.Errorf("error reading response message length from peer %s: %w", p2pPeer, err)
		return peerMetaInfo{}, err0
	}

	msgLen := binary.BigEndian.Uint16(msgLenBytes[:])
	msgBytes := make([]byte, msgLen)
	rn, err = stream.Read(msgBytes[:])
	if rn != int(msgLen) || err != nil {
		err0 := fmt.Errorf("error reading response message from peer %s: %w, expected: %d, read: %d", p2pPeer, err, msgLen, rn)
		return peerMetaInfo{}, err0
	}
	var responseHeaders peerMetaHeaders
	_, err = responseHeaders.UnmarshalMsg(msgBytes[:])
	if err != nil {
		err0 := fmt.Errorf("error unmarshaling response message from peer %s: %w", p2pPeer, err)
		return peerMetaInfo{}, err0
	}
	headers := peerMetaHeadersToHTTPHeaders(responseHeaders)
	matchingVersion, _ := checkProtocolVersionMatch(headers, netProtoSupportedVersions)
	if matchingVersion == "" {
		err0 := fmt.Errorf("peer %s does not support any of the supported protocol versions: %v", p2pPeer, netProtoSupportedVersions)
		return peerMetaInfo{}, err0
	}
	return peerMetaInfo{
		telemetryID:  headers.Get(TelemetryIDHeader),
		instanceName: headers.Get(InstanceNameHeader),
		version:      matchingVersion,
		features:     headers.Get(PeerFeaturesHeader),
	}, nil
}

func writePeerMetaHeaders(stream io.ReadWriter, p2pPeer peer.ID, networkProtoVersion string, pmp peerMetadataProvider) error {
	header := make(http.Header)
	setHeaders(header, networkProtoVersion, pmp)
	meta := peerMetaHeadersFromHTTPHeaders(header)
	data := meta.MarshalMsg(nil)
	length := len(data)
	if length > math.MaxUint16 {
		// 64k is enough for everyone
		// current headers size is 250 bytes
		msg := fmt.Sprintf("error writing initial message, too large: %v, peer %s", header, p2pPeer)
		panic(msg)
	}
	metaMsg := make([]byte, 2+length)
	binary.BigEndian.PutUint16(metaMsg, uint16(length))
	copy(metaMsg[2:], data)
	_, err := stream.Write(metaMsg)
	if err != nil {
		err0 := fmt.Errorf("error sending initial message: %w", err)
		return err0
	}
	return nil
}
