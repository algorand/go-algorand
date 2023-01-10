// Copyright (C) 2019-2023 Algorand, Inc.
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

package crypto

import "errors"

var (
	errInvalidVersion           = errors.New("Invalid version")
	errInvalidAddress           = errors.New("Invalid address")
	errInvalidThreshold         = errors.New("Invalid threshold")
	errInvalidNumberOfSignature = errors.New("Invalid number of signatures")
	errKeyNotExist              = errors.New("Key does not exist")
	errKeysNotMatch             = errors.New("Public key lists do not match")
	errInvalidDuplicates        = errors.New("Invalid duplicates")
	errInvalidNumberOfSig       = errors.New("invalid number of signatures to add")
)

var errUnknownVersion = errors.New("unknown version")
