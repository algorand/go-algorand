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

package hashable

import (
	"github.com/algorand/go-algorand/protocol"
)

// Message is used for messages with no special meaning
type Message struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	Message string   `codec:"msg"`
}

// ToBeHashed implements the crypto.Hashable interface
func (msg Message) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Message, protocol.Encode(&msg)
}
