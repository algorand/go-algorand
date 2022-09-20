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

package logic

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	BLS12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	BN254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	BN254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	BLS12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

/*Remaining questions
->What conditions should cause pairing to error vs put false on stack vs ignore point?
->Empty inputs (currently pairing and multiexp panic on empty inputs)
->Is subgroup check necessary for multiexp? Precompile does not seem to think so, but should ask Fabris
->Confirm with gnark whether or not IsInSubgroup() also checks if point on curve. If not, they have a problem
->For now our code is written as if IsInSubgroup() does not check if point is on curve but is set up to be easily changed
*/

// Note: comments are generally only listed once even if they apply to multiple different lines to avoid congestion from bls/bn/g1/g2 quadruplication
// Effectively this means input/output explanations are only given for bls12-381 g1 versions of funcs
// The input/output comments start around line 178
const (
	bls12381fpSize  = 48
	bls12381g1Size  = 2 * bls12381fpSize
	bls12381fp2Size = 2 * bls12381fpSize
	bls12381g2Size  = 2 * bls12381fp2Size
	bn254fpSize     = 32
	bn254g1Size     = 2 * bn254fpSize
	bn254fp2Size    = 2 * bn254fpSize
	bn254g2Size     = 2 * bn254fp2Size
	scalarSize      = 32
)

func bytesToBLS12381Field(b []byte) (BLS12381fp.Element, error) {
	intRepresentation := new(big.Int).SetBytes(b)
	if intRepresentation.Cmp(BLS12381fp.Modulus()) >= 0 {
		return BLS12381fp.Element{}, errors.New("Field element larger than modulus")
	}
	return *new(BLS12381fp.Element).SetBigInt(intRepresentation), nil
}

func bytesToBLS12381G1(b []byte, checkCurve bool) (bls12381.G1Affine, error) {
	var point bls12381.G1Affine
	var err error
	if len(b) != bls12381g1Size {
		return point, errors.New("Improper encoding")
	}
	point.X, err = bytesToBLS12381Field(b[:bls12381fpSize])
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	point.Y, err = bytesToBLS12381Field(b[bls12381fpSize:bls12381g1Size])
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	if checkCurve && !point.IsOnCurve() {
		return bls12381.G1Affine{}, errors.New("Point not on curve")
	}
	return point, nil
}

func bytesToBLS12381G1s(b []byte, checkSubgroup bool) ([]bls12381.G1Affine, error) {
	if len(b)%(bls12381g1Size) != 0 {
		return nil, errors.New("Improper encoding")
	}
	if len(b) == 0 {
		return nil, errors.New("Empty input")
	}
	points := make([]bls12381.G1Affine, len(b)/(bls12381g1Size))
	for i := 0; i < len(b)/(bls12381g1Size); i++ {
		// If IsInSubgroup() checks if point is on curve as well, the following line should replace the line after it
		// point, err := bytesToBLS12381G1(b[i*bls12381g1Size:(i+1)*bls12381g1Size], !checkSubgroup)
		point, err := bytesToBLS12381G1(b[i*bls12381g1Size:(i+1)*bls12381g1Size], true)
		if err != nil {
			// revisit later to see if way to check in one step if any errored instead of having to check each one
			return nil, err
		}
		if checkSubgroup && !point.IsInSubGroup() {
			return nil, errors.New("Wrong subgroup")
		}
		points[i] = point
	}
	return points, nil
}

func bytesToBLS12381G2(b []byte, checkCurve bool) (bls12381.G2Affine, error) {
	if len(b) != bls12381g2Size {
		return bls12381.G2Affine{}, errors.New("Improper encoding")
	}
	var err error
	var point bls12381.G2Affine
	point.X.A0, err = bytesToBLS12381Field(b[:bls12381fpSize])
	if err != nil {
		return bls12381.G2Affine{}, err
	}
	point.X.A1, err = bytesToBLS12381Field(b[bls12381fpSize : 2*bls12381fpSize])
	if err != nil {
		return bls12381.G2Affine{}, err
	}
	point.Y.A0, err = bytesToBLS12381Field(b[2*bls12381fpSize : 3*bls12381fpSize])
	if err != nil {
		return bls12381.G2Affine{}, err
	}
	point.Y.A1, err = bytesToBLS12381Field(b[3*bls12381fpSize : 4*bls12381fpSize])
	if err != nil {
		return bls12381.G2Affine{}, err
	}
	if checkCurve && !point.IsOnCurve() {
		return bls12381.G2Affine{}, errors.New("Point not on curve")
	}
	return point, nil
}

func bytesToBLS12381G2s(b []byte, checkSubgroup bool) ([]bls12381.G2Affine, error) {
	if len(b)%(bls12381g2Size) != 0 {
		return nil, errors.New("Improper encoding")
	}
	if len(b) == 0 {
		return nil, errors.New("Empty input")
	}
	points := make([]bls12381.G2Affine, len(b)/bls12381g2Size)
	for i := 0; i < len(b)/bls12381g2Size; i++ {
		// point, err := bytesToBLS12381G2(b[i*bls12381g2Size : (i+1)*bls12381g2Size], !checkSubgroup)
		point, err := bytesToBLS12381G2(b[i*bls12381g2Size:(i+1)*bls12381g2Size], true)
		if err != nil {
			return nil, err
		}
		if checkSubgroup && !point.IsInSubGroup() {
			return nil, errors.New("Wrong subgroup")
		}
		points[i] = point
	}
	return points, nil
}

func bls12381G1ToBytes(g1 *bls12381.G1Affine) []byte {
	retX := g1.X.Bytes()
	retY := g1.Y.Bytes()
	return append(retX[:], retY[:]...)
}

func bls12381G2ToBytes(g2 *bls12381.G2Affine) []byte {
	xFirst := g2.X.A0.Bytes()
	xSecond := g2.X.A1.Bytes()
	yFirst := g2.Y.A0.Bytes()
	ySecond := g2.Y.A1.Bytes()
	pointBytes := make([]byte, bls12381g2Size)
	copy(pointBytes, xFirst[:])
	copy(pointBytes[bls12381fpSize:], xSecond[:])
	copy(pointBytes[bls12381fp2Size:], yFirst[:])
	copy(pointBytes[bls12381fp2Size+bls12381fpSize:], ySecond[:])
	return pointBytes
}

// Input: Two byte slices at top of stack, each an uncompressed point
// Output: Single byte slice on top of stack which is the uncompressed sum of inputs
func opBLS12381G1Add(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	aBytes := cx.Stack[prev].Bytes
	bBytes := cx.Stack[last].Bytes
	a, err := bytesToBLS12381G1(aBytes, true)
	if err != nil {
		return err
	}
	b, err := bytesToBLS12381G1(bBytes, true)
	if err != nil {
		return err
	}
	// Would be slightly more efficient to use global variable instead of constantly creating new points
	// But would mess with parallelization
	res := new(bls12381.G1Affine).Add(&a, &b)
	// It's possible it's more efficient to only check if the sum is on the curve as opposed to the summands,
	// but I doubt that's safe
	resBytes := bls12381G1ToBytes(res)
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = resBytes
	return nil
}

func opBLS12381G2Add(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	aBytes := cx.Stack[prev].Bytes
	bBytes := cx.Stack[last].Bytes
	a, err := bytesToBLS12381G2(aBytes, true)
	if err != nil {
		return err
	}
	b, err := bytesToBLS12381G2(bBytes, true)
	if err != nil {
		return err
	}
	res := new(bls12381.G2Affine).Add(&a, &b)
	resBytes := bls12381G2ToBytes(res)
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = resBytes
	return nil
}

// Input: Two byte slices, top is bytes for scalar, second to top is uncompressed bytes for g1 point
// Output: Single byte slice on top of stack which contains uncompressed bytes for product of scalar and point
func opBLS12381G1ScalarMul(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	aBytes := cx.Stack[prev].Bytes
	a, err := bytesToBLS12381G1(aBytes, true)
	if err != nil {
		return err
	}
	kBytes := cx.Stack[last].Bytes
	if len(kBytes) != scalarSize {
		return fmt.Errorf("Scalars must be %d bytes long", scalarSize)
	}
	// Would probably be more efficient to use uint32
	k := new(big.Int).SetBytes(kBytes[:]) // what is purpose of slicing to self? Keeping it just b/c it was in original implementation
	res := new(bls12381.G1Affine).ScalarMultiplication(&a, k)
	resBytes := bls12381G1ToBytes(res)
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = resBytes
	return nil
}

func opBLS12381G2ScalarMul(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	aBytes := cx.Stack[prev].Bytes
	a, err := bytesToBLS12381G2(aBytes, true)
	if err != nil {
		return err
	}
	kBytes := cx.Stack[last].Bytes
	if len(kBytes) != scalarSize {
		return fmt.Errorf("Scalars must be %d bytes long", scalarSize)
	}
	k := new(big.Int).SetBytes(kBytes[:])
	res := new(bls12381.G2Affine).ScalarMultiplication(&a, k)
	resBytes := bls12381G2ToBytes(res)
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = resBytes
	return nil
}

// Input: Two byte slices, top is concatenated uncompressed bytes for k g2 points, and second to top is same for g1
// Output: Single uint at top representing bool for whether pairing of inputs was identity
func opBLS12381Pairing(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	g1Bytes := cx.Stack[prev].Bytes
	g2Bytes := cx.Stack[last].Bytes
	g1, err := bytesToBLS12381G1s(g1Bytes, true)
	if err != nil {
		return err
	}
	g2, err := bytesToBLS12381G2s(g2Bytes, true)
	if err != nil {
		return err
	}
	ok, err := bls12381.PairingCheck(g1, g2)
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Uint = boolToUint(ok)
	cx.Stack[prev].Bytes = nil
	// I'm assuming it's significantly more likely that err is nil than not
	return err
}

// Input: Top of stack is slice of k scalars, second to top is slice of k G1 points as uncompressed bytes
// Output: Single byte slice that contains uncompressed bytes for g1 point equivalent to p_1^e_1 * p_2^e_2 * ... * p_k^e_k, where p_i is i'th point from input and e_i is i'th scalar
func opBLS12381G1MultiExponentiation(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	g1Bytes := cx.Stack[prev].Bytes
	scalarBytes := cx.Stack[last].Bytes
	// Precompile does not list subgroup check as mandatory for multiexponentiation, but should ask Fabris about this
	g1Points, err := bytesToBLS12381G1s(g1Bytes, false)
	if err != nil {
		return err
	}
	if len(scalarBytes)%scalarSize != 0 || len(scalarBytes)/scalarSize != len(g1Points) {
		return errors.New("Bad input")
	}
	scalars := make([]BLS12381fr.Element, len(g1Points))
	for i := 0; i < len(g1Points); i++ {
		scalars[i].SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
	}
	res, _ := new(bls12381.G1Affine).MultiExp(g1Points, scalars, ecc.MultiExpConfig{})
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = bls12381G1ToBytes(res)
	return nil
}

func opBLS12381G2MultiExponentiation(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	g2Bytes := cx.Stack[prev].Bytes
	scalarBytes := cx.Stack[last].Bytes
	g2Points, err := bytesToBLS12381G2s(g2Bytes, false)
	if err != nil {
		return err
	}
	if len(scalarBytes)%scalarSize != 0 || len(scalarBytes)/scalarSize != len(g2Points) {
		return errors.New("Bad input")
	}
	scalars := make([]BLS12381fr.Element, len(g2Points))
	for i := 0; i < len(g2Points); i++ {
		scalars[i].SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
	}
	res, _ := new(bls12381.G2Affine).MultiExp(g2Points, scalars, ecc.MultiExpConfig{})
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = bls12381G2ToBytes(res)
	return nil
}

// Input: Single byte slice on top of stack representing single g1 field element
// Output: Single byte slice on top of stack which contains uncompressed bytes for g1 point (mapped to by input)
func opBLS12381MapFpToG1(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	fpBytes := cx.Stack[last].Bytes
	if len(fpBytes) != bls12381fpSize {
		return errors.New("Bad input")
	}
	fp, err := bytesToBLS12381Field(fpBytes)
	if err != nil {
		return err
	}
	point := bls12381.MapToG1(fp)
	cx.Stack[last].Bytes = bls12381G1ToBytes(&point)
	return nil
}

func opBLS12381MapFp2ToG2(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	fpBytes := cx.Stack[last].Bytes
	if len(fpBytes) != bls12381fp2Size {
		return errors.New("Bad input")
	}
	fp2 := new(bls12381.G2Affine).X
	var err error
	fp2.A0, err = bytesToBLS12381Field(fpBytes[0:bls12381fpSize])
	if err != nil {
		return err
	}
	fp2.A1, err = bytesToBLS12381Field(fpBytes[bls12381fpSize:])
	if err != nil {
		return err
	}
	point := bls12381.MapToG2(fp2)
	cx.Stack[last].Bytes = bls12381G2ToBytes(&point)
	return nil
}

// Input: Single byte slice on top of stack containing uncompressed bytes for g1 point
// Output: Single uint on stack top representing bool for whether the input was in the correct subgroup or not
func opBLS12381G1SubgroupCheck(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	pointBytes := cx.Stack[last].Bytes
	// checkCurve should be false if turns out that IsInSubgroup checks if point is on curve
	point, err := bytesToBLS12381G1(pointBytes, true)
	if err != nil {
		return err
	}
	cx.Stack[last].Uint = boolToUint(point.IsInSubGroup())
	cx.Stack[last].Bytes = nil
	return err
}

func opBLS12381G2SubgroupCheck(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	pointBytes := cx.Stack[last].Bytes
	point, err := bytesToBLS12381G2(pointBytes, true)
	if err != nil {
		return err
	}
	cx.Stack[last].Uint = boolToUint(point.IsInSubGroup())
	cx.Stack[last].Bytes = nil
	return err
}

func bytesToBN254Field(b []byte) (BN254fp.Element, error) {
	intRepresentation := new(big.Int).SetBytes(b)
	if intRepresentation.Cmp(BN254fp.Modulus()) >= 0 {
		return BN254fp.Element{}, errors.New("Field element larger than modulus")
	}
	return *new(BN254fp.Element).SetBigInt(intRepresentation), nil
}

func bytesToBN254G1(b []byte, checkCurve bool) (bn254.G1Affine, error) {
	var point bn254.G1Affine
	var err error
	if len(b) != bn254g1Size {
		return point, errors.New("Improper encoding")
	}
	point.X, err = bytesToBN254Field(b[:bn254fpSize])
	if err != nil {
		return bn254.G1Affine{}, err
	}
	point.Y, err = bytesToBN254Field(b[bn254fpSize:bn254g1Size])
	if err != nil {
		return bn254.G1Affine{}, err
	}
	if checkCurve && !point.IsOnCurve() {
		return bn254.G1Affine{}, errors.New("Point not on curve")
	}
	return point, nil
}

func bytesToBN254G1s(b []byte, checkSubgroup bool) ([]bn254.G1Affine, error) {
	if len(b)%(bn254g1Size) != 0 {
		return nil, errors.New("Improper encoding")
	}
	if len(b) == 0 {
		return nil, errors.New("Empty input")
	}
	points := make([]bn254.G1Affine, len(b)/(bn254g1Size))
	for i := 0; i < len(b)/(bn254g1Size); i++ {
		// point, err := bytesToBN254G1(b[i*bn254g1Size : (i+1)*bn254g1Size], !checkSubgroup)
		point, err := bytesToBN254G1(b[i*bn254g1Size:(i+1)*bn254g1Size], true)
		if err != nil {
			return nil, err
		}
		if checkSubgroup && !point.IsInSubGroup() {
			return nil, errors.New("Wrong subgroup")
		}
		points[i] = point
	}
	return points, nil
}

func bytesToBN254G2(b []byte, checkCurve bool) (bn254.G2Affine, error) {
	if len(b) != bn254g2Size {
		return bn254.G2Affine{}, errors.New("Improper encoding")
	}
	var err error
	var point bn254.G2Affine
	point.X.A0, err = bytesToBN254Field(b[:bn254fpSize])
	if err != nil {
		return bn254.G2Affine{}, err
	}
	point.X.A1, err = bytesToBN254Field(b[bn254fpSize : 2*bn254fpSize])
	if err != nil {
		return bn254.G2Affine{}, err
	}
	point.Y.A0, err = bytesToBN254Field(b[2*bn254fpSize : 3*bn254fpSize])
	if err != nil {
		return bn254.G2Affine{}, err
	}
	point.Y.A1, err = bytesToBN254Field(b[3*bn254fpSize : 4*bn254fpSize])
	if err != nil {
		return bn254.G2Affine{}, err
	}
	if checkCurve && !point.IsOnCurve() {
		return bn254.G2Affine{}, errors.New("Point not on curve")
	}
	return point, nil
}

func bytesToBN254G2s(b []byte, checkSubgroup bool) ([]bn254.G2Affine, error) {
	if len(b)%(bn254g2Size) != 0 {
		return nil, errors.New("Improper encoding")
	}
	if len(b) == 0 {
		return nil, errors.New("Empty input")
	}
	points := make([]bn254.G2Affine, len(b)/bn254g2Size)
	for i := 0; i < len(b)/bn254g2Size; i++ {
		// point, err := bytesToBN254G2(b[i*bn254g2Size : (i+1)*bn254g2Size], !checkSubgroup)
		point, err := bytesToBN254G2(b[i*bn254g2Size:(i+1)*bn254g2Size], true)
		if err != nil {
			return nil, err
		}
		if checkSubgroup && !point.IsInSubGroup() {
			return nil, errors.New("Wrong subgroup")
		}
		points[i] = point
	}
	return points, nil
}

func bn254G1ToBytes(g1 *bn254.G1Affine) []byte {
	retX := g1.X.Bytes()
	retY := g1.Y.Bytes()
	return append(retX[:], retY[:]...)
}

func bn254G2ToBytes(g2 *bn254.G2Affine) []byte {
	xFirst := g2.X.A0.Bytes()
	xSecond := g2.X.A1.Bytes()
	yFirst := g2.Y.A0.Bytes()
	ySecond := g2.Y.A1.Bytes()
	pointBytes := make([]byte, bn254g2Size)
	copy(pointBytes, xFirst[:])
	copy(pointBytes[bn254fpSize:], xSecond[:])
	copy(pointBytes[bn254fp2Size:], yFirst[:])
	copy(pointBytes[bn254fp2Size+bn254fpSize:], ySecond[:])
	return pointBytes
}

func opBN254G1Add(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	aBytes := cx.Stack[prev].Bytes
	bBytes := cx.Stack[last].Bytes
	a, err := bytesToBN254G1(aBytes, true)
	if err != nil {
		return err
	}
	b, err := bytesToBN254G1(bBytes, true)
	if err != nil {
		return err
	}
	res := new(bn254.G1Affine).Add(&a, &b)
	resBytes := bn254G1ToBytes(res)
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = resBytes
	return nil
}

func opBN254G2Add(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	aBytes := cx.Stack[prev].Bytes
	bBytes := cx.Stack[last].Bytes
	a, err := bytesToBN254G2(aBytes, true)
	if err != nil {
		return err
	}
	b, err := bytesToBN254G2(bBytes, true)
	if err != nil {
		return err
	}
	res := new(bn254.G2Affine).Add(&a, &b)
	resBytes := bn254G2ToBytes(res)
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = resBytes
	return nil
}

func opBN254G1ScalarMul(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	aBytes := cx.Stack[prev].Bytes
	a, err := bytesToBN254G1(aBytes, true)
	if err != nil {
		return err
	}
	kBytes := cx.Stack[last].Bytes
	if len(kBytes) != scalarSize {
		return fmt.Errorf("Scalars must be %d bytes long", scalarSize)
	}
	k := new(big.Int).SetBytes(kBytes[:])
	res := new(bn254.G1Affine).ScalarMultiplication(&a, k)
	resBytes := bn254G1ToBytes(res)
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = resBytes
	return nil
}

func opBN254G2ScalarMul(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	aBytes := cx.Stack[prev].Bytes
	a, err := bytesToBN254G2(aBytes, true)
	if err != nil {
		return err
	}
	kBytes := cx.Stack[last].Bytes
	if len(kBytes) != scalarSize {
		return fmt.Errorf("Scalars must be %d bytes long", scalarSize)
	}
	k := new(big.Int).SetBytes(kBytes[:])
	res := new(bn254.G2Affine).ScalarMultiplication(&a, k)
	resBytes := bn254G2ToBytes(res)
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = resBytes
	return nil
}

func opBN254Pairing(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	g1Bytes := cx.Stack[prev].Bytes
	g2Bytes := cx.Stack[last].Bytes
	g1, err := bytesToBN254G1s(g1Bytes, true)
	if err != nil {
		return err
	}
	g2, err := bytesToBN254G2s(g2Bytes, true)
	if err != nil {
		return err
	}
	ok, err := bn254.PairingCheck(g1, g2)
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev] = boolToSV(ok)
	return err
}

func opBN254G1MultiExponentiation(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	g1Bytes := cx.Stack[prev].Bytes
	scalarBytes := cx.Stack[last].Bytes
	g1Points, err := bytesToBN254G1s(g1Bytes, false)
	if err != nil {
		return err
	}
	if len(scalarBytes)%scalarSize != 0 || len(scalarBytes)/scalarSize != len(g1Points) {
		return errors.New("Bad input")
	}
	scalars := make([]BN254fr.Element, len(g1Points))
	for i := 0; i < len(g1Points); i++ {
		scalars[i].SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
	}
	res, _ := new(bn254.G1Affine).MultiExp(g1Points, scalars, ecc.MultiExpConfig{})
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = bn254G1ToBytes(res)
	return nil
}

func opBN254G2MultiExponentiation(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	prev := last - 1
	g2Bytes := cx.Stack[prev].Bytes
	scalarBytes := cx.Stack[last].Bytes
	g2Points, err := bytesToBN254G2s(g2Bytes, false)
	if err != nil {
		return err
	}
	if len(scalarBytes)%scalarSize != 0 || len(scalarBytes)/scalarSize != len(g2Points) {
		return errors.New("Bad input")
	}
	scalars := make([]BN254fr.Element, len(g2Points))
	for i := 0; i < len(g2Points); i++ {
		scalars[i].SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
	}
	res, _ := new(bn254.G2Affine).MultiExp(g2Points, scalars, ecc.MultiExpConfig{})
	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = bn254G2ToBytes(res)
	return nil
}

func opBN254MapFpToG1(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	fpBytes := cx.Stack[last].Bytes
	if len(fpBytes) != bn254fpSize {
		return errors.New("Bad input")
	}
	// should be MapToG1 in most recent version
	fp, err := bytesToBN254Field(fpBytes)
	if err != nil {
		return err
	}
	point := bn254.MapToG1(fp)
	cx.Stack[last].Bytes = bn254G1ToBytes(&point)
	return nil
}

func opBN254MapFp2ToG2(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	fpBytes := cx.Stack[last].Bytes
	if len(fpBytes) != bn254fp2Size {
		return errors.New("Bad input")
	}
	fp2 := new(bn254.G2Affine).X
	var err error
	fp2.A0, err = bytesToBN254Field(fpBytes[0:bn254fpSize])
	if err != nil {
		return err
	}
	fp2.A1, err = bytesToBN254Field(fpBytes[bn254fpSize:])
	if err != nil {
		return err
	}
	point := bn254.MapToG2(fp2)
	cx.Stack[last].Bytes = bn254G2ToBytes(&point)
	return nil
}

func opBN254G1SubgroupCheck(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	pointBytes := cx.Stack[last].Bytes
	point, err := bytesToBN254G1(pointBytes, true)
	if err != nil {
		return err
	}
	cx.Stack[last].Uint = boolToUint(point.IsInSubGroup())
	cx.Stack[last].Bytes = nil
	return err
}

func opBN254G2SubgroupCheck(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	pointBytes := cx.Stack[last].Bytes
	point, err := bytesToBN254G2(pointBytes, true)
	if err != nil {
		return err
	}
	cx.Stack[last].Uint = boolToUint(point.IsInSubGroup())
	cx.Stack[last].Bytes = nil
	return err
}
