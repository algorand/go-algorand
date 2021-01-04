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

package tokens

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/algorand/go-algorand/util"
)

const minimumAPITokenLength = 64
const maximumAPITokenLength = 256

// API tokens that live in the datadirs of their respective daemons
const (
	AlgodTokenFilename      = "algod.token"
	AlgodAdminTokenFilename = "algod.admin.token"
	KmdTokenFilename        = "kmd.token"
)

func tokenFilepath(dataDir, tokenFilename string) string {
	return filepath.Join(dataDir, tokenFilename)
}

// GetAndValidateAPIToken reads the APIToken from the token file and validates
// it. Always returns the potentially invalid token along with the error
func GetAndValidateAPIToken(dataDir, tokenFilename string) (string, error) {
	filepath := tokenFilepath(dataDir, tokenFilename)
	apiToken, err := util.GetFirstLineFromFile(filepath)

	// Failed to read token from file
	if err != nil {
		return apiToken, err
	}

	// Check if the token we read is reasonable
	err = ValidateAPIToken(apiToken)

	return apiToken, err
}

// writeAPITokenToDisk persists the APIToken to the datadir
func writeAPITokenToDisk(dataDir, tokenFilename, apiToken string) error {
	filepath := tokenFilepath(dataDir, tokenFilename)
	return ioutil.WriteFile(filepath, []byte(apiToken), 0644)
}

// GenerateAPIToken writes a cryptographically secure APIToken to disk
func GenerateAPIToken(dataDir, tokenFilename string) (string, error) {
	// Random bytes will be converted to hex to make token
	var entropyLen = (minimumAPITokenLength + 1) / 2
	tokenBytes := make([]byte, entropyLen)

	// From rand.Read docs: "On return, n == len(b) if and only if err == nil."
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("error reading random bytes: %v", err)
	}

	// Convert random bytes to hex
	hexToken := fmt.Sprintf("%x", tokenBytes)

	// Ensure we generated a valid token
	err = ValidateAPIToken(hexToken)
	if err != nil {
		return "", fmt.Errorf("generated invalid token: %v", err)
	}

	// Persist the token to disk
	return hexToken, writeAPITokenToDisk(dataDir, tokenFilename, hexToken)
}

// ValidateAPIToken returns a non-nil error if the passed APIToken fails our
// validation checks
func ValidateAPIToken(apiToken string) error {
	if len(apiToken) < minimumAPITokenLength {
		return fmt.Errorf("provided APIToken too short. Must be >= %d characters", minimumAPITokenLength)
	}

	if len(apiToken) > maximumAPITokenLength {
		return fmt.Errorf("provided APIToken too long. Must be <= %d characters", maximumAPITokenLength)
	}

	return nil
}

// ValidateOrGenerateAPIToken generates an APIToken if it does not exist, and
// checks that any set token is valid
func ValidateOrGenerateAPIToken(dataDir, tokenFilename string) (apiToken string, wroteToken bool, err error) {
	// Get an existing APIToken, if it exists.
	apiToken, _ = GetAndValidateAPIToken(dataDir, tokenFilename)

	// If there's no existing APIToken, generate one
	if apiToken == "" {
		apiToken, err = GenerateAPIToken(dataDir, tokenFilename)
		if err != nil {
			return
		}
		wroteToken = true
	}

	// Now check for any errors with the new/old token
	err = ValidateAPIToken(apiToken)

	return
}
