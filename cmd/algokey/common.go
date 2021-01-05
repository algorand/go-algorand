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

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/passphrase"
)

const (
	stdoutFilenameValue = "-"
	stdinFileNameValue  = "-"
)

func loadKeyfileOrMnemonic(keyfile string, mnemonic string) crypto.Seed {
	if keyfile != "" && mnemonic != "" {
		fmt.Fprintf(os.Stderr, "Cannot specify both keyfile and mnemonic\n")
		os.Exit(1)
	}

	if keyfile != "" {
		return loadKeyfile(keyfile)
	}

	if mnemonic != "" {
		return loadMnemonic(mnemonic)
	}

	fmt.Fprintf(os.Stderr, "Must specify one of keyfile or mnemonic\n")
	os.Exit(1)

	panic("unreachable")
}

func loadMnemonic(mnemonic string) crypto.Seed {
	seedbytes, err := passphrase.MnemonicToKey(mnemonic)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot recover key seed from mnemonic: %v\n", err)
		os.Exit(1)
	}

	var seed crypto.Seed
	copy(seed[:], seedbytes)
	return seed
}

func loadKeyfile(keyfile string) crypto.Seed {
	seedbytes, err := ioutil.ReadFile(keyfile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read key seed from %s: %v\n", keyfile, err)
		os.Exit(1)
	}

	var seed crypto.Seed
	copy(seed[:], seedbytes)
	return seed
}

func writePrivateKey(keyfile string, seed crypto.Seed) {
	err := ioutil.WriteFile(keyfile, seed[:], 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write key to %s: %v\n", keyfile, err)
		os.Exit(1)
	}
}

func writePublicKey(pubkeyfile string, checksummed string) {
	data := fmt.Sprintf("%s\n", checksummed)
	err := ioutil.WriteFile(pubkeyfile, []byte(data), 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write public key to %s: %v\n", pubkeyfile, err)
		os.Exit(1)
	}
}

func computeMnemonic(seed crypto.Seed) string {
	mnemonic, err := passphrase.KeyToMnemonic(seed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot generate key mnemonic: %v\n", err)
		os.Exit(1)
	}
	return mnemonic
}

// writeFile is a wrapper of ioutil.WriteFile which considers the special
// case of stdout filename
func writeFile(filename string, data []byte, perm os.FileMode) error {
	var err error
	if filename == stdoutFilenameValue {
		// Write to Stdout
		if _, err = os.Stdout.Write(data); err != nil {
			return err
		}
		return nil
	}
	return ioutil.WriteFile(filename, data, perm)
}

// readFile is a wrapper of ioutil.ReadFile which considers the
// special case of stdin filename
func readFile(filename string) ([]byte, error) {
	if filename == stdinFileNameValue {
		return ioutil.ReadAll(os.Stdin)
	}
	return ioutil.ReadFile(filename)
}
