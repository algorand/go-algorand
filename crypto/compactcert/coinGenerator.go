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

package compactcert

import (
	"math/big"

	"golang.org/x/crypto/sha3"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// The coinChoiceSeed defines the randomness seed that will be given to an XOF function. This will be used  for choosing
// the index of the coin to reveal as part of the compact certificate.
type coinChoiceSeed struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SignedWeight uint64                `codec:"sigweight"`
	Sigcom       crypto.GenericDigest  `codec:"sigcom"`
	Partcom      crypto.GenericDigest  `codec:"partcom"`
	MsgHash      StateProofMessageHash `codec:"msghash"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (cc coinChoiceSeed) ToBeHashed() (protocol.HashID, []byte) {
	// TODO should create a fixed length representation
	return protocol.CompactCertCoin, protocol.Encode(&cc)
}

// coinGenerator is used for extracting "randomized" 64 bits for coin flips
type coinGenerator struct {
	shkContext   sha3.ShakeHash
	signedWeight uint64
}

// makeCoinGenerator creates a new CoinHash context.
// it is used for squeezing 64 bits for coin flips.
// the function inits the XOF function in the following manner
// Shake(sumhash(coinChoiceSeed))
//we extract 64 bits from shake for each coin flip and divide it by SignedWeight
func makeCoinGenerator(choice coinChoiceSeed) coinGenerator {
	hash := crypto.HashFactory{HashType: CoinHashType}.NewHash()
	hashedCoin := crypto.GenericHashObj(hash, choice)

	shk := sha3.NewShake256()
	shk.Write(hashedCoin)

	return coinGenerator{shkContext: shk, signedWeight: choice.SignedWeight}
}

// getNextCoin returns the next 64bits integer which represents a number between [0,SignedWeight)
func (ch *coinGenerator) getNextCoin() uint64 {
	var shakeDigest [8]byte

	ch.shkContext.Read(shakeDigest[:])

	i := &big.Int{}
	i.SetBytes(shakeDigest[:])

	w := &big.Int{}
	w.SetUint64(ch.signedWeight)

	res := &big.Int{}
	res.Mod(i, w)
	return res.Uint64()
}
