// Copyright (C) 2020 Algorand, Inc.
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
	"encoding/binary"
	"fmt"
	"io"

	//	"github.com/algorand/go-algorand/crypto"
)

// Topic is a key-value pair
type Topic struct {
	key string
	data []byte
}

// Topics is an array of type Topic
type Topics []Topic

// MarshalTopics serializes the topics into a byte array
func (ta Topics) MarshalTopics()(b []byte, e error) {

	// Calculate the total buffer size required to store the topics
	bufferSize := binary.MaxVarintLen32 // store topic array size

	for _, val := range ta {
		bufferSize += 2*binary.MaxVarintLen32 // store key size and the data size
		bufferSize += len(val.key)
		bufferSize += len(val.data)
	}

	
	buffer := make([]byte, bufferSize)
	bidx := binary.PutUvarint(buffer, uint64(len(ta)))	
	for _, val := range ta {
		// write the key size
		n := binary.PutUvarint(buffer[bidx:], uint64(len(val.key)))
		bidx +=n
		// write the key
		n = copy(buffer[bidx:], []byte(val.key))
		bidx += n

		// write the data size
		n = binary.PutUvarint(buffer[bidx:], uint64(len(val.data)))
		bidx += n
		// write the data
		n = copy(buffer[bidx:], val.data)
		bidx += n
	}

	// the size could be smaller than estimated because used
	// MaxVarintLen32 instead of the real size during estimation
	if bidx > bufferSize { 
		e = fmt.Errorf("Unexpected error during Marshalling.!")
	}
	return buffer, e
}

// Unmarshall the topics from the byte array
func UnmarshalTopics(buffer []byte) (ts Topics, err error) {
	reader := bytes.NewReader(buffer)

	// Get the number of topics
	numTopics, e := binary.ReadUvarint(reader)
	if e != nil {
		return nil, e
	}
	topics := make([]Topic, numTopics)
	
	for x:=0; x < int(numTopics); x++ {
		// read the key length
		len, e := binary.ReadUvarint(reader)
		if e != nil {
			return nil, e
		}
		// read the key
		tmpBuffer := make([]byte, len)
		_, e = io.ReadAtLeast(reader, tmpBuffer, int(len))
		if e != nil {
			return nil, e
		}
		topics[x].key = string(tmpBuffer)

		// read the data length
		len, e = binary.ReadUvarint(reader)
		if e != nil {
			return nil, e
		}
		// read the data
		topics[x].data = make([]byte, len)
		_, e = io.ReadAtLeast(reader, topics[x].data, int(len))
		if e != nil {
			return nil, e
		}
	}
	return topics, e
}
