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


type Topic struct {
	key string
	data []byte
}

type Topics []Topic

func (ta Topics) MarshalTopics()(b []byte, e error) {
	bufferSize := binary.MaxVarintLen32 // 1 for the size of topic array
	
	for _, val := range ta {
		bufferSize += 2*binary.MaxVarintLen32 // 1 for key size, one for data size
		bufferSize += len(val.key)
		bufferSize += len(val.data)
	}

	buffer := make([]byte, bufferSize)
	bidx := binary.PutUvarint(buffer, uint64(len(ta)))	
	for _, val := range ta {
		// copy the key
		n := binary.PutUvarint(buffer[bidx:], uint64(len(val.key)))
		bidx +=n 
		n = copy(buffer[bidx:], []byte(val.key))
		bidx += n

		// copy the data
		n = binary.PutUvarint(buffer[bidx:], uint64(len(val.data)))
		bidx += n
		n = copy(buffer[bidx:], val.data)
		bidx += n
	}
	if bidx > bufferSize {
		e = fmt.Errorf("Topic Marshal is broken!")
	}
	return buffer, e
}

func UnmarshalTopics(buffer []byte) (ts Topics, err error) {
	reader := bytes.NewReader(buffer)
	numTopics, e := binary.ReadUvarint(reader)
	if e != nil {
		return nil, e
	}
	topics := make([]Topic, numTopics)
	
	for x:=0; x < int(numTopics); x++ {
		len, e := binary.ReadUvarint(reader)
		if e != nil {
			return nil, e
		}
		tmpBuffer := make([]byte, len)
		io.ReadFull(io.LimitReader(reader, int64(len)), tmpBuffer)
		topics[x].key = string(tmpBuffer)
		len, e = binary.ReadUvarint(reader)
		topics[x].data = make([]byte, len)
		io.ReadFull(io.LimitReader(reader, int64(len)), topics[x].data)
	}
	return topics, e
}
