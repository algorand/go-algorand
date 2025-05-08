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
	"net/http"
	"testing"

	"github.com/algorand/go-algorand/logging"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockStream is a io.ReaderWriter testing mock
type MockStream struct {
	mock.Mock
}

func (m *MockStream) Read(p []byte) (n int, err error) {
	args := m.Called(p)
	arg0 := args.Get(0).([]byte)
	copy(p, arg0)
	return len(arg0), args.Error(1)
}

func (m *MockStream) Write(p []byte) (n int, err error) {
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

func TestReadPeerMetaHeaders(t *testing.T) {
	mockStream := new(MockStream)
	p2pPeer := peer.ID("mockPeer")
	n := &P2PNetwork{
		log:                       logging.Base(),
		supportedProtocolVersions: []string{"1.0", "2.2"},
	}

	httpHeaders := make(http.Header)
	httpHeaders.Set(TelemetryIDHeader, "mockTelemetryID")
	httpHeaders.Set(InstanceNameHeader, "mockInstanceName")
	httpHeaders.Set(ProtocolVersionHeader, "1.0")
	httpHeaders.Set(ProtocolAcceptVersionHeader, "1.0")
	httpHeaders.Set(PeerFeaturesHeader, "mockFeatures")
	headers := peerMetaHeadersFromHTTPHeaders(httpHeaders)
	data := headers.MarshalMsg(nil)
	length := uint16(len(data))
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, length)

	mockStream.On("Read", mock.Anything).Return(lengthBytes, nil).Once()
	mockStream.On("Read", mock.Anything).Return(data, nil).Once()

	metaInfo, err := readPeerMetaHeaders(mockStream, p2pPeer, n.supportedProtocolVersions)
	assert.NoError(t, err)
	assert.Equal(t, "mockTelemetryID", metaInfo.telemetryID)
	assert.Equal(t, "mockInstanceName", metaInfo.instanceName)
	assert.Equal(t, "1.0", metaInfo.version)
	assert.Equal(t, "mockFeatures", metaInfo.features)
	mockStream.AssertExpectations(t)
}

func TestWritePeerMetaHeaders(t *testing.T) {
	mockStream := new(MockStream)
	p2pPeer := peer.ID("mockPeer")
	n := &P2PNetwork{
		log: logging.Base(),
	}

	header := make(http.Header)
	setHeaders(header, "1.0", n)
	meta := peerMetaHeadersFromHTTPHeaders(header)
	data := meta.MarshalMsg(nil)
	length := uint16(len(data))
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, length)

	mockStream.On("Write", append(lengthBytes, data...)).Return(len(lengthBytes)+len(data), nil).Once()

	err := writePeerMetaHeaders(mockStream, p2pPeer, "1.0", n)
	assert.NoError(t, err)
	mockStream.AssertExpectations(t)
}
