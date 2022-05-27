// Copyright (C) 2019-2022 Algorand, Inc.
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

/*
   This file contains code to adjust the json serialization of
   Transaction. Currently the only change from the standard serialization
   provided by the codec package is to cause BoxRefs to be serialized with b64
   names, rather than the default for string, which would not properly encode
   their binary nature in JSON.

   Had we done it from the beginning, it would be reasonable to do the same for
   some other fields that are declared as string, but can contain arbitrary
   binary data, such as AssetParams fields like unitname and url. We can't do
   that now, to preserve the shape of our REST APIs. But perhaps we can do it
   for a v3 REST API.

*/

package transactions

import "github.com/algorand/go-algorand/protocol"

type boxRefStringly struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	Index   uint64   `codec:"i"`
	Name    []byte   `codec:"n"`
}

// MarshalJSON makes it so BoxRefs emit b64 encoded names
func (br BoxRef) MarshalJSON() ([]byte, error) {
	return protocol.EncodeJSON(boxRefStringly{
		Index: br.Index,
		Name:  []byte(br.Name),
	}), nil
}

// UnmarshalJSON makes it so BoxRefs read u64 names
func (br *BoxRef) UnmarshalJSON(data []byte) error {
	var x boxRefStringly
	err := protocol.DecodeJSON(data, &x)
	if err != nil {
		return err
	}
	br.Index = x.Index
	br.Name = string(x.Name)
	return nil
}
