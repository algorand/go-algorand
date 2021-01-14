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

package network

import (
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
)

// Constant strings used as keys for topics
const (
	requestHashKey = "RequestHash"
	ErrorKey       = "Error" // used for passing an error message
)

// Topic is a key-value pair
type Topic struct {
	key  string
	data []byte
}

// MakeTopic Creates a Topic
func MakeTopic(key string, data []byte) Topic {
	return Topic{key: key, data: data}
}

// Topics is an array of type Topic
// The maximum number of topics allowed is 32
// Each topic key can be 64 characters long and cannot be size 0
type Topics []Topic

// MarshallTopics serializes the topics into a byte array
func (ts Topics) MarshallTopics() (b []byte) {

	// Calculate the total buffer size required to store the topics
	bufferSize := binary.MaxVarintLen32 // store topic array size

	for _, val := range ts {
		bufferSize += 2 * binary.MaxVarintLen32 // store key size and the data size
		bufferSize += len(val.key)
		bufferSize += len(val.data)
	}

	buffer := make([]byte, bufferSize)
	bidx := binary.PutUvarint(buffer, uint64(len(ts)))
	for _, val := range ts {
		// write the key size
		n := binary.PutUvarint(buffer[bidx:], uint64(len(val.key)))
		bidx += n
		// write the key
		n = copy(buffer[bidx:], val.key)
		bidx += n

		// write the data size
		n = binary.PutUvarint(buffer[bidx:], uint64(len(val.data)))
		bidx += n
		// write the data
		n = copy(buffer[bidx:], val.data)
		bidx += n
	}
	return buffer[:bidx]
}

// UnmarshallTopics unmarshalls the topics from the byte array
func UnmarshallTopics(buffer []byte) (ts Topics, err error) {
	// Get the number of topics
	var idx int
	numTopics, nr := binary.Uvarint(buffer[idx:])
	if nr <= 0 {
		return nil, fmt.Errorf("UnmarshallTopics: could not read the number of topics")
	}
	if numTopics > 32 { // numTopics is uint64
		return nil, fmt.Errorf("UnmarshallTopics: number of topics %d is greater than 32", numTopics)
	}
	idx += nr
	topics := make([]Topic, numTopics)

	for x := 0; x < int(numTopics); x++ {
		// read the key length
		strlen, nr := binary.Uvarint(buffer[idx:])
		if nr <= 0 {
			return nil, fmt.Errorf("UnmarshallTopics: could not read the key length")
		}
		idx += nr

		// read the key
		if len(buffer) < idx+int(strlen) || strlen > 64 || strlen == 0 {
			return nil, fmt.Errorf("UnmarshallTopics: could not read the key")
		}
		topics[x].key = string(buffer[idx : idx+int(strlen)])
		idx += int(strlen)

		// read the data length
		dataLen, nr := binary.Uvarint(buffer[idx:])
		if nr <= 0 {
			return nil, fmt.Errorf("UnmarshallTopics: could not read the data length")
		}
		idx += nr

		// read the data
		if len(buffer) < idx+int(dataLen) {
			return nil, fmt.Errorf("UnmarshallTopics: data larger than buffer size")
		}
		topics[x].data = make([]byte, dataLen)
		copy(topics[x].data, buffer[idx:idx+int(dataLen)])
		idx += int(dataLen)
	}
	return topics, nil
}

// hashTopics returns the hash of serialized topics.
// Expects the nonce to be already added as a topic
func hashTopics(topics []byte) (partialHash uint64) {
	digest := crypto.Hash(topics)
	partialHash = digest.TrimUint64()
	return partialHash
}

// GetValue returns the value of the key if the key is found in the topics
func (ts *Topics) GetValue(key string) (val []byte, found bool) {
	for _, t := range *ts {
		if t.key == key {
			return t.data, true
		}
	}
	return
}
