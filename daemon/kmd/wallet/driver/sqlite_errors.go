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

package driver

import (
	"fmt"
)

var errDatabase = fmt.Errorf("database error")
var errDatabaseConnect = fmt.Errorf("error connecting to database")
var errKeyNotFound = fmt.Errorf("key does not exist in this wallet")
var errMsigDataNotFound = fmt.Errorf("multisig information (pks, threshold) for address does not exist in this wallet")
var errSKToPK = fmt.Errorf("could not convert secret key to public key")
var errSKToSeed = fmt.Errorf("could not convert secret key to seed")
var errTampering = fmt.Errorf("derived public key mismatch, something fishy is going on with this wallet")
var errNoMnemonicUX = fmt.Errorf("sqlite wallet driver cannot display mnemonics")
var errKeyExists = fmt.Errorf("key already exists in wallet")
var errDeriveKey = fmt.Errorf("scrypt lib could not derive key from password")
var errWrongDriver = fmt.Errorf("found database with wrong driver name in wallets dir")
var errRandBytes = fmt.Errorf("error reading random bytes")
var errTooManyKeys = fmt.Errorf("too many keys")
var errWrongDriverVer = fmt.Errorf("found database with wrong driver version in wallets dir")
var errDecrypt = fmt.Errorf("error decrypting. wrong password?")
var errTypeMismatch = fmt.Errorf("error decrypting, found the wrong type of data. something fishy is going on with this wallet")
var errSameName = fmt.Errorf("wallet with same name already exists")
var errSameID = fmt.Errorf("wallet with same id already exists")
var errIDConflict = fmt.Errorf("multiple wallets with the same ID exist. cannot continue")
var errWalletNotFound = fmt.Errorf("wallet not found")
var errSQLiteWrongType = fmt.Errorf("sqlite wallet driver returned wrong wallet type")
var errNameTooLong = fmt.Errorf("wallet name too long, must be <= %d bytes", sqliteMaxWalletNameLen)
var errIDTooLong = fmt.Errorf("wallet id too long, must be <= %d bytes", sqliteMaxWalletIDLen)
var errMsigWrongAddr = fmt.Errorf("given multisig preimage hashes to neither Sender nor AuthAddr")
var errMsigWrongKey = fmt.Errorf("given key is not a possible signer for this multisig")
