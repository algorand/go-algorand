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

package passphrase

import (
	"crypto/sha512"
	"fmt"
	"strings"
)

const (
	bitsPerWord      = 11
	checksumLenBits  = 11
	keyLenBytes      = 32
	mnemonicLenWords = 25
	paddingZeros     = bitsPerWord - ((keyLenBytes * 8) % bitsPerWord)
)

var sepStr = " "
var emptyByte = byte(0)

func init() {
	// Verify expected relationship between constants
	if mnemonicLenWords*bitsPerWord-checksumLenBits != keyLenBytes*8+paddingZeros {
		panic("cannot initialize passphrase library: invalid constants")
	}
}

// KeyToMnemonic converts a 32-byte key into a 25 word mnemonic. The generated
// mnemonic includes a checksum. Each word in the mnemonic represents 11 bits
// of data, and the last 11 bits are reserved for the checksum.
func KeyToMnemonic(key []byte) (string, error) {
	// Ensure the key we are passed is the expected length
	if len(key) != keyLenBytes {
		return "", errWrongKeyLen
	}

	// Compute the checksum of these bytes
	chk := checksum(key)
	uint11Array := toUint11Array(key)
	words := applyWords(uint11Array, wordlist)
	return fmt.Sprintf("%s %s", strings.Join(words, " "), chk), nil
}

// MnemonicToKey converts a mnemonic generated using this library into the
// source key used to create it. It returns an error if the passed mnemonic
// has an incorrect checksum, if the number of words is unexpected, or if one
// of the passed words is not found in the words list.
func MnemonicToKey(mnemonic string) ([]byte, error) {
	// Split input on whitespace
	wordsRaw := strings.Split(mnemonic, sepStr)

	// Strip out extra whitespace
	var words []string
	for _, word := range wordsRaw {
		if word != "" {
			words = append(words, word)
		}
	}

	// Ensure the mnemonic is the correct length
	if len(words) != mnemonicLenWords {
		return nil, errWrongMnemonicLen
	}

	// Check that all words are in list
	for _, w := range words {
		if indexOf(wordlist, w) == -1 {
			return nil, fmt.Errorf("%s is not in the words list", w)
		}
	}

	// convert words to uin11array (Excluding the checksum word)
	var uint11Array []uint32
	for i := 0; i < len(words)-1; i++ {
		uint11Array = append(uint11Array, uint32(indexOf(wordlist, words[i])))
	}

	// convert t the key back to byte array
	byteArr := toByteArray(uint11Array)

	// We need to chop the last byte -
	// the short explanation - Since 256 is not divisible by 11, we have an extra 0x0 byte.
	// The longer explanation - When splitting the 256 bits to chunks of 11, we get 23 words and a left over of 3 bits.
	// This left gets padded with another 8 bits to the create the 24th word.
	// While converting back to byte array, our new 264 bits array is divisible by 8 but the last byte is just the padding.

	// Check that we have 33 bytes long array as expected
	if len(byteArr) != keyLenBytes+1 {
		return nil, errWrongKeyLen
	}
	// Check that the last one is actually 0
	if byteArr[keyLenBytes] != emptyByte {
		return nil, errWrongChecksum
	}

	// chop it !
	byteArr = byteArr[0:keyLenBytes]

	// Pull out the checksum
	mnemonicChecksum := checksum(byteArr)

	// Verify the checksum
	if mnemonicChecksum != words[len(words)-1] {
		return nil, errWrongChecksum
	}

	// Verify that we recovered the correct amount of data
	if len(byteArr) != keyLenBytes {
		panic("passphrase:MnemonicToKey is broken: recovered wrong amount of data")
	}

	return byteArr, nil
}

// https://stackoverflow.com/a/50285590/356849
func toUint11Array(arr []byte) []uint32 {
	var buffer uint32
	var numberOfBit uint32
	var output []uint32

	for i := 0; i < len(arr); i++ {
		// prepend bits to buffer
		buffer |= uint32(arr[i]) << numberOfBit
		numberOfBit += 8

		// if there enough bits, extract 11bit number
		if numberOfBit >= 11 {
			// 0x7FF is 2047, the max 11 bit number
			output = append(output, buffer&0x7ff)

			// drop chunk from buffer
			buffer = buffer >> 11
			numberOfBit -= 11
		}

	}

	if numberOfBit != 0 {
		output = append(output, buffer&0x7ff)
	}
	return output
}

// This function may result in an extra empty byte
// https://stackoverflow.com/a/51452614
func toByteArray(arr []uint32) []byte {
	var buffer uint32
	var numberOfBits uint32
	var output []byte

	for i := 0; i < len(arr); i++ {
		buffer |= uint32(arr[i]) << numberOfBits
		numberOfBits += 11

		for numberOfBits >= 8 {
			output = append(output, byte(buffer&0xff))
			buffer >>= 8
			numberOfBits -= 8
		}
	}

	if numberOfBits != 0 {
		output = append(output, byte(buffer))
	}

	return output
}

func applyWords(arr []uint32, words []string) []string {
	res := make([]string, len(arr))
	for i := 0; i < len(arr); i++ {
		res[i] = words[arr[i]]
	}
	return res
}

func indexOf(arr []string, s string) int {
	for i, w := range arr {
		if w == s {
			return i
		}
	}
	return -1
}

// Checksum returns a word that represents the 11 bit checksum of the data
func checksum(data []byte) string {
	// Compute the full hash of the data to checksum
	fullHash := sha512.Sum512_256(data)

	// Convert to 11 bits array
	temp := fullHash[0:2]
	chkBytes := toUint11Array(temp)

	return applyWords(chkBytes, wordlist)[0]
}
