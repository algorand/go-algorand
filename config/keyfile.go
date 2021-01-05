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

package config

import (
	"fmt"
	"strconv"
	"strings"
)

// rootKeyFilenameFormat is a format string for the files that hold root keys.
const rootKeyFilenameFormat = "%s.rootkey"

// partKeyFilenameFormat is a format string for the files that hold participation keys.
const partKeyFilenameFormat = "%s.%d.%d.partkey"

func extractPartValidInterval(filename string) (fValid, lValid uint64, ok bool) {
	parts := strings.Split(filename, ".")
	np := len(parts)
	if np < 4 {
		return 0, 0, false
	}

	var err error
	lValid, err = strconv.ParseUint(parts[np-2], 10, 0)
	if err != nil {
		return 0, 0, false
	}
	fValid, err = strconv.ParseUint(parts[np-3], 10, 0)
	if err != nil {
		return 0, 0, false
	}

	if fValid > lValid {
		return 0, 0, false
	}

	return fValid, lValid, true
}

// RootKeyFilename gives the root key filename that corresponds to the given account
// name.
func RootKeyFilename(s string) string {
	return fmt.Sprintf(rootKeyFilenameFormat, s)
}

// PartKeyFilename gives the participation key filename that corresponds to the given
// account name and validity period.
func PartKeyFilename(s string, firstValid, lastValid uint64) string {
	return fmt.Sprintf(partKeyFilenameFormat, s, firstValid, lastValid)
}

// MatchesRootKeyFilename returns true if the given filename is the root key file of
// the given account name.
func MatchesRootKeyFilename(s, filename string) bool {
	return RootKeyFilename(s) == filename
}

// MatchesPartKeyFilename returns true if the given filename is the participation key
// file of the given account name.
func MatchesPartKeyFilename(s, filename string) bool {
	fValid, lValid, ok := extractPartValidInterval(filename)
	return ok && PartKeyFilename(s, fValid, lValid) == filename
}

// IsRootKeyFilename returns true if the given filename is a valid root key filename.
func IsRootKeyFilename(filename string) bool {
	n := AccountNameFromRootKeyFilename(filename)
	return MatchesRootKeyFilename(n, filename)
}

// IsPartKeyFilename returns true if the given filename is a valid participation key
// filename.
func IsPartKeyFilename(filename string) bool {
	n := AccountNameFromPartKeyFilename(filename)
	return MatchesPartKeyFilename(n, filename)
}

// AccountNameFromRootKeyFilename returns the account name given a root key filename.
//
// If filename is not a valid root key filename, this returns the filename unchanged.
func AccountNameFromRootKeyFilename(filename string) string {
	return strings.TrimSuffix(filename, ".rootkey")
}

// AccountNameFromPartKeyFilename returns the account name given a participation key
// filename.
//
// If filename is not a valid participation key filename, this returns the filename
// unchanged.
func AccountNameFromPartKeyFilename(filename string) string {
	fValid, lValid, ok := extractPartValidInterval(filename)
	if !ok {
		return filename
	}

	suffix := fmt.Sprintf(".%d.%d.partkey", fValid, lValid)
	return strings.TrimSuffix(filename, suffix)
}
