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

package libgoal

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
)

// ImportKey wraps imports a secret key into the kmd wallet using the passed walletHandle
func (c *Client) ImportKey(walletHandle []byte, secretKey []byte) (response kmdapi.APIV1POSTKeyImportResponse, err error) {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}
	var tmpSK crypto.PrivateKey
	copy(tmpSK[:], secretKey)
	return kmd.ImportKey(walletHandle, tmpSK)
}
