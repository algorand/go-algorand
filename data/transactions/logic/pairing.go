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

package logic

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

func bytesToBN254Field(b []byte) (ret fp.Element) {
	ret.SetBytes(b)
	return
}

func bytesToBN254G1(b []byte) (ret bn254.G1Affine) {
	ret.X = bytesToBN254Field(b[:32])
	ret.Y = bytesToBN254Field(b[32:64])
	return
}

func bytesToBN254G1s(b []byte) (ret []bn254.G1Affine) {
	for i := 0; i < len(b)/64; i++ {
		ret = append(ret, bytesToBN254G1(b[(i*64):(i*64+64)]))
	}
	return
}

func bytesToBN254G2(b []byte) (ret bn254.G2Affine) {
	ret.X.A0 = bytesToBN254Field(b[:32])
	ret.X.A1 = bytesToBN254Field(b[32:64])
	ret.Y.A0 = bytesToBN254Field(b[64:96])
	ret.Y.A1 = bytesToBN254Field(b[96:128])
	return
}

func bytesToBN254G2s(b []byte) (ret []bn254.G2Affine) {
	for i := 0; i < len(b)/128; i++ {
		ret = append(ret, bytesToBN254G2(b[(i*128):(i*128+128)]))
	}
	return
}

func bN254G1ToBytes(g1 *bn254.G1Affine) (ret []byte) {
	retX := g1.X.Bytes()
	retY := g1.Y.Bytes()
	ret = append(retX[:], retY[:]...)
	return
}

func opBn256Add(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	bBytes := cx.stack[last].Bytes
	if len(aBytes) != 64 || len(bBytes) != 64 {
		return errors.New("expect G1 in 64 bytes")
	}
	a := bytesToBN254G1(aBytes)
	b := bytesToBN254G1(bBytes)
	res := new(bn254.G1Affine).Add(&a, &b)
	resBytes := bN254G1ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBn256ScalarMul(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	aBytes := cx.stack[prev].Bytes
	if len(aBytes) != 64 {
		return errors.New("expect G1 in 64 bytes")
	}
	a := bytesToBN254G1(aBytes)
	kBytes := cx.stack[last].Bytes
	k := new(big.Int).SetBytes(kBytes[:])
	res := new(bn254.G1Affine).ScalarMultiplication(&a, k)
	resBytes := bN254G1ToBytes(res)
	cx.stack = cx.stack[:last]
	cx.stack[prev].Bytes = resBytes
	return nil
}

func opBn256Pairing(cx *EvalContext) error {
	last := len(cx.stack) - 1
	prev := last - 1
	g1Bytes := cx.stack[prev].Bytes
	g2Bytes := cx.stack[last].Bytes
	g1 := bytesToBN254G1s(g1Bytes)
	g2 := bytesToBN254G2s(g2Bytes)
	ok, err := bn254.PairingCheck(g1, g2)
	if err != nil {
		return errors.New("pairing failed")
	}
	cx.stack = cx.stack[:last]
	cx.stack[prev].Uint = boolToUint(ok)
	cx.stack[prev].Bytes = nil
	return nil
}
