// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

	"filippo.io/edwards25519"
	edfield "filippo.io/edwards25519/field"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type sError string

func (s sError) Error() string { return string(s) }

const (
	errNotOnCurve    = sError("point not on curve")
	errWrongSubgroup = sError("wrong subgroup")
	errEmptyInput    = sError("empty input")
)

// Input: Two byte slices at top of stack, each an uncompressed point
// Output: Single byte slice on top of stack which is the uncompressed sum of inputs
func opEcAdd(cx *EvalContext) error {
	group := EcGroup(cx.program[cx.pc+1])
	fs, ok := ecGroupSpecByField(group)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid ec_add group %s", group)
	}

	last := len(cx.Stack) - 1
	prev := last - 1
	a := cx.Stack[prev].Bytes
	b := cx.Stack[last].Bytes

	var res []byte
	var err error
	switch fs.field {
	case BN254g1:
		res, err = bn254G1Add(a, b)
	case BN254g2:
		res, err = bn254G2Add(a, b)
	case BLS12_381g1:
		res, err = bls12381G1Add(a, b)
	case BLS12_381g2:
		res, err = bls12381G2Add(a, b)
	case ED25519:
		res, err = ed25519Add(a, b)
	default:
		err = fmt.Errorf("invalid ec_add group %s", group)
	}
	cx.Stack[prev].Bytes = res
	cx.Stack = cx.Stack[:last]
	return err
}

// Input: ToS is a scalar, encoded as an unsigned big-endian, second to top are
// bytes of an uncompressed point
// Output: Single byte slice on top of stack which contains uncompressed bytes
// for product of scalar and point
func opEcScalarMul(cx *EvalContext) error {
	group := EcGroup(cx.program[cx.pc+1])
	fs, ok := ecGroupSpecByField(group)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid ec_scalar_mul group %s", group)
	}

	last := len(cx.Stack) - 1
	prev := last - 1
	aBytes := cx.Stack[prev].Bytes
	kBytes := cx.Stack[last].Bytes
	if len(kBytes) > scalarSize {
		return fmt.Errorf("ec_scalar_mul scalar len is %d, exceeds 32", len(kBytes))
	}
	k := new(big.Int).SetBytes(kBytes)

	var res []byte
	var err error
	switch fs.field {
	case BN254g1:
		res, err = bn254G1ScalarMul(aBytes, k)
	case BN254g2:
		res, err = bn254G2ScalarMul(aBytes, k)
	case BLS12_381g1:
		res, err = bls12381G1ScalarMul(aBytes, k)
	case BLS12_381g2:
		res, err = bls12381G2ScalarMul(aBytes, k)
	case ED25519:
		res, err = ed25519ScalarMul(aBytes, k)
	default:
		err = fmt.Errorf("invalid ec_scalar_mul group %s", group)
	}

	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = res
	return err
}

// Input: Two byte slices, The first (deeper) is concatenated uncompressed bytes
// for k points of the curve given as the immediate value. The second (ToS) are
// k points for the "associated" curve.
// Output: bool (uint64=0,1) for whether pairing of inputs was identity
func opEcPairingCheck(cx *EvalContext) error {
	group := EcGroup(cx.program[cx.pc+1])
	fs, ok := ecGroupSpecByField(group)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid ec_pairing_check group %s", group)
	}

	last := len(cx.Stack) - 1
	prev := last - 1
	g1Bytes := cx.Stack[prev].Bytes
	g2Bytes := cx.Stack[last].Bytes

	var err error
	ok = false
	switch fs.field {
	case BN254g2:
		g1Bytes, g2Bytes = g2Bytes, g1Bytes
		fallthrough
	case BN254g1:
		ok, err = bn254PairingCheck(g1Bytes, g2Bytes)
	case BLS12_381g2:
		g1Bytes, g2Bytes = g2Bytes, g1Bytes
		fallthrough
	case BLS12_381g1:
		ok, err = bls12381PairingCheck(g1Bytes, g2Bytes)
	default:
		err = fmt.Errorf("invalid ec_pairing_check group %s", group)
	}

	cx.Stack = cx.Stack[:last]
	cx.Stack[prev] = boolToSV(ok)
	return err
}

// Input: Top of stack is slice of k scalars, second to top is slice of k group points as uncompressed bytes
// Output: Single byte slice that contains uncompressed bytes for point equivalent to
// p_1*e_1 + p_2*e_2 + ... + p_k*e_k, where p_i is i'th point from input and e_i is i'th scalar
func opEcMultiScalarMul(cx *EvalContext) error {
	group := EcGroup(cx.program[cx.pc+1])
	fs, ok := ecGroupSpecByField(group)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid ec_multi_scalar_mul group %s", group)
	}

	last := len(cx.Stack) - 1
	prev := last - 1
	pointBytes := cx.Stack[prev].Bytes
	scalarBytes := cx.Stack[last].Bytes

	var res []byte
	var err error
	switch fs.field {
	case BN254g1:
		res, err = bn254G1MultiMul(pointBytes, scalarBytes)
	case BN254g2:
		res, err = bn254G2MultiMul(pointBytes, scalarBytes)
	case BLS12_381g1:
		res, err = bls12381G1MultiMul(pointBytes, scalarBytes)
	case BLS12_381g2:
		res, err = bls12381G2MultiMul(pointBytes, scalarBytes)
	case ED25519:
		res, err = ed25519MultiMul(pointBytes, scalarBytes)
	default:
		err = fmt.Errorf("invalid ec_multi_scalar_mul group %s", group)
	}

	cx.Stack = cx.Stack[:last]
	cx.Stack[prev].Bytes = res
	return err
}

// Input: Single byte slice on top of stack containing uncompressed bytes for a point
// Output: bool (uint64=0,1) for whether the input was in the correct subgroup or not
func opEcSubgroupCheck(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	pointBytes := cx.Stack[last].Bytes

	group := EcGroup(cx.program[cx.pc+1])
	fs, ok := ecGroupSpecByField(group)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid ec_subgroup_check group %s", group)
	}

	var err error
	ok = false
	switch fs.field {
	case BN254g1:
		ok, err = bn254G1SubgroupCheck(pointBytes)
	case BN254g2:
		ok, err = bn254G2SubgroupCheck(pointBytes)
	case BLS12_381g1:
		ok, err = bls12381G1SubgroupCheck(pointBytes)
	case BLS12_381g2:
		ok, err = bls12381G2SubgroupCheck(pointBytes)
	case ED25519:
		ok, err = ed25519SubgroupCheck(pointBytes)
	default:
		err = fmt.Errorf("invalid ec_subgroup_check group %s", group)
	}

	cx.Stack[last] = boolToSV(ok)
	return err
}

// Input: Single byte slice on top of stack representing single field element
// Output: Single byte slice on top of stack which contains uncompressed bytes
// for corresponding point (mapped to by input)
func opEcMapTo(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	fpBytes := cx.Stack[last].Bytes

	group := EcGroup(cx.program[cx.pc+1])
	fs, ok := ecGroupSpecByField(group)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid ec_map_to group %s", group)
	}

	var res []byte
	var err error
	switch fs.field {
	case BN254g1:
		res, err = bn254MapToG1(fpBytes)
	case BN254g2:
		res, err = bn254MapToG2(fpBytes)
	case BLS12_381g1:
		res, err = bls12381MapToG1(fpBytes)
	case BLS12_381g2:
		res, err = bls12381MapToG2(fpBytes)
	case ED25519:
		res, err = ed25519MapTo(fpBytes)
	case ED25519_Monero:
		res, err = ed25519MoneroMapTo(fpBytes)
	default:
		err = fmt.Errorf("invalid ec_map_to group %s", group)
	}
	cx.Stack[last].Bytes = res
	return err
}

const (
	bls12381fpSize  = 48
	bls12381g1Size  = 2 * bls12381fpSize
	bls12381fp2Size = 2 * bls12381fpSize
	bls12381g2Size  = 2 * bls12381fp2Size

	bn254fpSize  = 32
	bn254g1Size  = 2 * bn254fpSize
	bn254fp2Size = 2 * bn254fpSize
	bn254g2Size  = 2 * bn254fp2Size

	ed25519fpSize    = 32
	ed25519PointSize = 2 * ed25519fpSize // uncompressed affine: 32 byte X then 32 byte Y, big-endian

	scalarSize = 32
)

var bls12381Modulus = bls12381fp.Modulus()

func bytesToBLS12381Field(b []byte) (bls12381fp.Element, error) {
	big := new(big.Int).SetBytes(b)
	if big.Cmp(bls12381Modulus) >= 0 {
		return bls12381fp.Element{}, fmt.Errorf("field element %s larger than modulus %s", big.String(), bls12381Modulus)
	}
	return *new(bls12381fp.Element).SetBigInt(big), nil
}

func bytesToBLS12381G1(b []byte) (bls12381.G1Affine, error) {
	if len(b) != bls12381g1Size {
		return bls12381.G1Affine{}, fmt.Errorf("bad length %d. Expected %d", len(b), bls12381g1Size)
	}
	var point bls12381.G1Affine
	var err error
	point.X, err = bytesToBLS12381Field(b[:bls12381fpSize])
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	point.Y, err = bytesToBLS12381Field(b[bls12381fpSize:bls12381g1Size])
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	if !point.IsOnCurve() {
		return bls12381.G1Affine{}, errNotOnCurve
	}
	return point, nil
}

func bytesToBLS12381G1s(b []byte, checkSubgroup bool) ([]bls12381.G1Affine, error) {
	if len(b)%bls12381g1Size != 0 {
		return nil, fmt.Errorf("bad length %d. Expected %d multiple", len(b), bls12381g1Size)
	}
	if len(b) == 0 {
		return nil, errEmptyInput
	}
	points := make([]bls12381.G1Affine, len(b)/bls12381g1Size)
	for i := range points {
		var err error
		points[i], err = bytesToBLS12381G1(b[i*bls12381g1Size : (i+1)*bls12381g1Size])
		if err != nil {
			return nil, err
		}
		if checkSubgroup && !points[i].IsInSubGroup() {
			return nil, errWrongSubgroup
		}
	}
	return points, nil
}

func bytesToBLS12381G2(b []byte) (bls12381.G2Affine, error) {
	if len(b) != bls12381g2Size {
		return bls12381.G2Affine{}, fmt.Errorf("bad length %d. Expected %d", len(b), bls12381g2Size)
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
	if !point.IsOnCurve() {
		return bls12381.G2Affine{}, errNotOnCurve
	}
	return point, nil
}

func bytesToBLS12381G2s(b []byte, checkSubgroup bool) ([]bls12381.G2Affine, error) {
	if len(b)%bls12381g2Size != 0 {
		return nil, fmt.Errorf("bad length %d. Expected %d multiple", len(b), bls12381g2Size)
	}
	if len(b) == 0 {
		return nil, errEmptyInput
	}
	points := make([]bls12381.G2Affine, len(b)/bls12381g2Size)
	for i := range points {
		var err error
		points[i], err = bytesToBLS12381G2(b[i*bls12381g2Size : (i+1)*bls12381g2Size])
		if err != nil {
			return nil, err
		}
		if checkSubgroup && !points[i].IsInSubGroup() {
			return nil, errWrongSubgroup
		}
	}
	return points, nil
}

func bls12381G1ToBytes(g1 *bls12381.G1Affine) []byte {
	retX := g1.X.Bytes()
	retY := g1.Y.Bytes()
	pointBytes := make([]byte, bls12381g1Size)
	copy(pointBytes, retX[:])
	copy(pointBytes[bls12381fpSize:], retY[:])
	return pointBytes
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

func bls12381G1Add(aBytes, bBytes []byte) ([]byte, error) {
	a, err := bytesToBLS12381G1(aBytes)
	if err != nil {
		return nil, err
	}
	b, err := bytesToBLS12381G1(bBytes)
	if err != nil {
		return nil, err
	}
	return bls12381G1ToBytes(a.Add(&a, &b)), nil
}

func bls12381G2Add(aBytes, bBytes []byte) ([]byte, error) {
	a, err := bytesToBLS12381G2(aBytes)
	if err != nil {
		return nil, err
	}
	b, err := bytesToBLS12381G2(bBytes)
	if err != nil {
		return nil, err
	}
	return bls12381G2ToBytes(a.Add(&a, &b)), nil
}

func bls12381G1ScalarMul(aBytes []byte, k *big.Int) ([]byte, error) {
	a, err := bytesToBLS12381G1(aBytes)
	if err != nil {
		return nil, err
	}
	return bls12381G1ToBytes(a.ScalarMultiplication(&a, k)), nil
}

func bls12381G2ScalarMul(aBytes []byte, k *big.Int) ([]byte, error) {
	a, err := bytesToBLS12381G2(aBytes)
	if err != nil {
		return nil, err
	}
	return bls12381G2ToBytes(a.ScalarMultiplication(&a, k)), nil
}

func bls12381PairingCheck(g1Bytes, g2Bytes []byte) (bool, error) {
	g1, err := bytesToBLS12381G1s(g1Bytes, true)
	if err != nil {
		return false, err
	}
	g2, err := bytesToBLS12381G2s(g2Bytes, true)
	if err != nil {
		return false, err
	}
	ok, err := bls12381.PairingCheck(g1, g2)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// We'll use a little concurrency to speed up the multiexp, but without a global
// mechanism to control parallelism across different modules, we'll just use 2.
var mecLimit = ecc.MultiExpConfig{
	NbTasks: 2,
}

const bls12381G1MultiMulThreshold = 2 // determined by BenchmarkFindMultiMulCutoff

func bls12381G1MultiMul(pointBytes, scalarBytes []byte) ([]byte, error) {
	points, err := bytesToBLS12381G1s(pointBytes, false)
	if err != nil {
		return nil, err
	}
	if len(scalarBytes) != scalarSize*len(points) {
		return nil, fmt.Errorf("bad scalars length %d. Expected %d", len(scalarBytes), scalarSize*len(points))
	}
	if len(points) <= bls12381G1MultiMulThreshold {
		return bls12381G1MultiMulSmall(points, scalarBytes)
	}
	return bls12381G1MultiMulLarge(points, scalarBytes)
}

func bls12381G1MultiMulLarge(points []bls12381.G1Affine, scalarBytes []byte) ([]byte, error) {
	scalars := make([]bls12381fr.Element, len(points))
	for i := range scalars {
		scalars[i].SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
	}
	res, err := new(bls12381.G1Affine).MultiExp(points, scalars, mecLimit)
	if err != nil {
		return nil, err
	}
	return bls12381G1ToBytes(res), nil
}

func bls12381G1MultiMulSmall(points []bls12381.G1Affine, scalarBytes []byte) ([]byte, error) {
	// There must be at least one point. Start with it, rather than the identity.
	k := new(big.Int).SetBytes(scalarBytes[:scalarSize])
	var sum bls12381.G1Affine
	sum.ScalarMultiplication(&points[0], k)
	for i := range points {
		if i == 0 {
			continue
		}
		k.SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
		var prod bls12381.G1Affine
		prod.ScalarMultiplication(&points[i], k)
		sum.Add(&sum, &prod)
	}
	return bls12381G1ToBytes(&sum), nil
}

const bls12381G2MultiMulThreshold = 2 // determined by BenchmarkFindMultiMulCutoff

func bls12381G2MultiMul(pointBytes, scalarBytes []byte) ([]byte, error) {
	points, err := bytesToBLS12381G2s(pointBytes, false)
	if err != nil {
		return nil, err
	}
	if len(scalarBytes) != scalarSize*len(points) {
		return nil, fmt.Errorf("bad scalars length %d. Expected %d", len(scalarBytes), scalarSize*len(points))
	}
	if len(points) <= bls12381G2MultiMulThreshold {
		return bls12381G2MultiMulSmall(points, scalarBytes)
	}
	return bls12381G2MultiMulLarge(points, scalarBytes)
}

func bls12381G2MultiMulLarge(points []bls12381.G2Affine, scalarBytes []byte) ([]byte, error) {
	scalars := make([]bls12381fr.Element, len(points))
	for i := range scalars {
		scalars[i].SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
	}
	res, err := new(bls12381.G2Affine).MultiExp(points, scalars, mecLimit)
	if err != nil {
		return nil, err
	}
	return bls12381G2ToBytes(res), nil
}

func bls12381G2MultiMulSmall(points []bls12381.G2Affine, scalarBytes []byte) ([]byte, error) {
	// There must be at least one point. Start with it, rather than the identity.
	k := new(big.Int).SetBytes(scalarBytes[:scalarSize])
	var sum bls12381.G2Jac
	sum.FromAffine(&points[0])
	sum.ScalarMultiplication(&sum, k)
	for i := range points {
		if i == 0 {
			continue
		}
		k.SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
		var prod bls12381.G2Jac
		prod.FromAffine(&points[i])
		prod.ScalarMultiplication(&prod, k)
		sum.AddAssign(&prod)
	}
	var res bls12381.G2Affine
	res.FromJacobian(&sum)
	return bls12381G2ToBytes(&res), nil
}

func bls12381MapToG1(fpBytes []byte) ([]byte, error) {
	fp, err := bytesToBLS12381Field(fpBytes)
	if err != nil {
		return nil, err
	}
	point := bls12381.MapToG1(fp)
	return bls12381G1ToBytes(&point), nil
}

func bls12381MapToG2(fpBytes []byte) ([]byte, error) {
	if len(fpBytes) != bls12381fp2Size {
		return nil, fmt.Errorf("bad encoded element length: %d", len(fpBytes))
	}
	g2 := bls12381.G2Affine{}
	var err error
	g2.X.A0, err = bytesToBLS12381Field(fpBytes[0:bls12381fpSize])
	if err != nil {
		return nil, err
	}
	g2.X.A1, err = bytesToBLS12381Field(fpBytes[bls12381fpSize:])
	if err != nil {
		return nil, err
	}
	point := bls12381.MapToG2(g2.X)
	return bls12381G2ToBytes(&point), nil
}

func bls12381G1SubgroupCheck(pointBytes []byte) (bool, error) {
	point, err := bytesToBLS12381G1(pointBytes)
	if err != nil {
		return false, err
	}
	return point.IsInSubGroup(), nil
}

func bls12381G2SubgroupCheck(pointBytes []byte) (bool, error) {
	point, err := bytesToBLS12381G2(pointBytes)
	if err != nil {
		return false, err
	}
	return point.IsInSubGroup(), nil
}

var bn254Modulus = bn254fp.Modulus()

func bytesToBN254Field(b []byte) (bn254fp.Element, error) {
	big := new(big.Int).SetBytes(b)
	if big.Cmp(bn254Modulus) >= 0 {
		return bn254fp.Element{}, fmt.Errorf("field element %s larger than modulus %s", big.String(), bn254Modulus)
	}
	return *new(bn254fp.Element).SetBigInt(big), nil
}

func bytesToBN254G1(b []byte) (bn254.G1Affine, error) {
	if len(b) != bn254g1Size {
		return bn254.G1Affine{}, fmt.Errorf("bad length %d. Expected %d", len(b), bn254g1Size)
	}
	var point bn254.G1Affine
	var err error
	point.X, err = bytesToBN254Field(b[:bn254fpSize])
	if err != nil {
		return bn254.G1Affine{}, err
	}
	point.Y, err = bytesToBN254Field(b[bn254fpSize:bn254g1Size])
	if err != nil {
		return bn254.G1Affine{}, err
	}
	if !point.IsOnCurve() {
		return bn254.G1Affine{}, errNotOnCurve
	}
	return point, nil
}

func bytesToBN254G1s(b []byte, checkSubgroup bool) ([]bn254.G1Affine, error) {
	if len(b)%bn254g1Size != 0 {
		return nil, fmt.Errorf("bad length %d. Expected %d multiple", len(b), bn254g1Size)
	}
	if len(b) == 0 {
		return nil, errEmptyInput
	}
	points := make([]bn254.G1Affine, len(b)/bn254g1Size)
	for i := range points {
		var err error
		points[i], err = bytesToBN254G1(b[i*bn254g1Size : (i+1)*bn254g1Size])
		if err != nil {
			return nil, err
		}
		if checkSubgroup && !points[i].IsInSubGroup() {
			return nil, errWrongSubgroup
		}
	}
	return points, nil
}

func bytesToBN254G2(b []byte) (bn254.G2Affine, error) {
	if len(b) != bn254g2Size {
		return bn254.G2Affine{}, fmt.Errorf("bad length %d. Expected %d", len(b), bn254g2Size)
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
	if !point.IsOnCurve() {
		return bn254.G2Affine{}, errNotOnCurve
	}
	return point, nil
}

func bytesToBN254G2s(b []byte, checkSubgroup bool) ([]bn254.G2Affine, error) {
	if len(b)%bn254g2Size != 0 {
		return nil, fmt.Errorf("bad length %d. Expected %d multiple", len(b), bn254g2Size)
	}
	if len(b) == 0 {
		return nil, errEmptyInput
	}
	points := make([]bn254.G2Affine, len(b)/bn254g2Size)
	for i := range points {
		var err error
		points[i], err = bytesToBN254G2(b[i*bn254g2Size : (i+1)*bn254g2Size])
		if err != nil {
			return nil, err
		}
		if checkSubgroup && !points[i].IsInSubGroup() {
			return nil, errWrongSubgroup
		}
	}
	return points, nil
}

func bn254G1ToBytes(g1 *bn254.G1Affine) []byte {
	retX := g1.X.Bytes()
	retY := g1.Y.Bytes()
	pointBytes := make([]byte, bn254g1Size)
	copy(pointBytes, retX[:])
	copy(pointBytes[bn254fpSize:], retY[:])
	return pointBytes
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

func bn254G1Add(aBytes, bBytes []byte) ([]byte, error) {
	a, err := bytesToBN254G1(aBytes)
	if err != nil {
		return nil, err
	}
	b, err := bytesToBN254G1(bBytes)
	if err != nil {
		return nil, err
	}
	return bn254G1ToBytes(a.Add(&a, &b)), nil
}

func bn254G2Add(aBytes, bBytes []byte) ([]byte, error) {
	a, err := bytesToBN254G2(aBytes)
	if err != nil {
		return nil, err
	}
	b, err := bytesToBN254G2(bBytes)
	if err != nil {
		return nil, err
	}
	return bn254G2ToBytes(a.Add(&a, &b)), nil
}

func bn254G1ScalarMul(aBytes []byte, k *big.Int) ([]byte, error) {
	a, err := bytesToBN254G1(aBytes)
	if err != nil {
		return nil, err
	}
	return bn254G1ToBytes(a.ScalarMultiplication(&a, k)), nil
}

func bn254G2ScalarMul(aBytes []byte, k *big.Int) ([]byte, error) {
	a, err := bytesToBN254G2(aBytes)
	if err != nil {
		return nil, err
	}
	return bn254G2ToBytes(a.ScalarMultiplication(&a, k)), nil
}

func bn254PairingCheck(g1Bytes, g2Bytes []byte) (bool, error) {
	g1, err := bytesToBN254G1s(g1Bytes, true)
	if err != nil {
		return false, err
	}
	g2, err := bytesToBN254G2s(g2Bytes, true)
	if err != nil {
		return false, err
	}
	ok, err := bn254.PairingCheck(g1, g2)
	if err != nil {
		return false, err
	}
	return ok, nil
}

const bn254G1MultiMulThreshold = 3 // determined by BenchmarkFindMultiMulCutoff

func bn254G1MultiMul(pointBytes, scalarBytes []byte) ([]byte, error) {
	points, err := bytesToBN254G1s(pointBytes, false)
	if err != nil {
		return nil, err
	}
	if len(scalarBytes) != scalarSize*len(points) {
		return nil, fmt.Errorf("bad scalars length %d. Expected %d", len(scalarBytes), scalarSize*len(points))
	}
	if len(points) <= bn254G1MultiMulThreshold {
		return bn254G1MultiMulSmall(points, scalarBytes)
	}
	return bn254G1MultiMulLarge(points, scalarBytes)
}

func bn254G1MultiMulLarge(points []bn254.G1Affine, scalarBytes []byte) ([]byte, error) {
	scalars := make([]bn254fr.Element, len(points))
	for i := range scalars {
		scalars[i].SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
	}
	res, err := new(bn254.G1Affine).MultiExp(points, scalars, mecLimit)
	if err != nil {
		return nil, err
	}
	return bn254G1ToBytes(res), nil
}

func bn254G1MultiMulSmall(points []bn254.G1Affine, scalarBytes []byte) ([]byte, error) {
	// There must be at least one point. Start with it, rather than the identity.
	k := new(big.Int).SetBytes(scalarBytes[:scalarSize])
	var sum bn254.G1Affine
	sum.ScalarMultiplication(&points[0], k)
	for i := range points {
		if i == 0 {
			continue
		}
		k.SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
		var prod bn254.G1Affine
		prod.ScalarMultiplication(&points[i], k)
		sum.Add(&sum, &prod)
	}
	return bn254G1ToBytes(&sum), nil
}

const bn254G2MultiMulThreshold = 2 // determined by BenchmarkFindMultiMulCutoff

func bn254G2MultiMul(pointBytes, scalarBytes []byte) ([]byte, error) {
	points, err := bytesToBN254G2s(pointBytes, false)
	if err != nil {
		return nil, err
	}
	if len(scalarBytes) != scalarSize*len(points) {
		return nil, fmt.Errorf("bad scalars length %d. Expected %d", len(scalarBytes), scalarSize*len(points))
	}
	if len(points) <= bn254G2MultiMulThreshold {
		return bn254G2MultiMulSmall(points, scalarBytes)
	}
	return bn254G2MultiMulLarge(points, scalarBytes)
}

func bn254G2MultiMulLarge(points []bn254.G2Affine, scalarBytes []byte) ([]byte, error) {
	scalars := make([]bn254fr.Element, len(points))
	for i := range scalars {
		scalars[i].SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
	}
	res, err := new(bn254.G2Affine).MultiExp(points, scalars, mecLimit)
	if err != nil {
		return nil, err
	}
	return bn254G2ToBytes(res), nil
}

func bn254G2MultiMulSmall(points []bn254.G2Affine, scalarBytes []byte) ([]byte, error) {
	// There must be at least one point. Start with it, rather than the identity.
	k := new(big.Int).SetBytes(scalarBytes[:scalarSize])
	var sum bn254.G2Jac
	sum.FromAffine(&points[0])
	sum.ScalarMultiplication(&sum, k)
	for i := range points {
		if i == 0 {
			continue
		}
		k.SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
		var prod bn254.G2Jac
		prod.FromAffine(&points[i])
		prod.ScalarMultiplication(&prod, k)
		sum.AddAssign(&prod)
	}
	var res bn254.G2Affine
	res.FromJacobian(&sum)
	return bn254G2ToBytes(&res), nil
}

func bn254MapToG1(fpBytes []byte) ([]byte, error) {
	fp, err := bytesToBN254Field(fpBytes)
	if err != nil {
		return nil, err
	}
	point := bn254.MapToG1(fp)
	return bn254G1ToBytes(&point), nil
}

func bn254MapToG2(fpBytes []byte) ([]byte, error) {
	if len(fpBytes) != bn254fp2Size {
		return nil, fmt.Errorf("bad encoded element length: %d", len(fpBytes))
	}
	fp2 := bn254.G2Affine{}.X // no way to declare an fptower.E2
	var err error
	fp2.A0, err = bytesToBN254Field(fpBytes[0:bn254fpSize])
	if err != nil {
		return nil, err
	}
	fp2.A1, err = bytesToBN254Field(fpBytes[bn254fpSize:])
	if err != nil {
		return nil, err
	}
	point := bn254.MapToG2(fp2)
	return bn254G2ToBytes(&point), nil
}

func bn254G1SubgroupCheck(pointBytes []byte) (bool, error) {
	point, err := bytesToBN254G1(pointBytes)
	if err != nil {
		return false, err
	}
	return point.IsInSubGroup(), nil
}

func bn254G2SubgroupCheck(pointBytes []byte) (bool, error) {
	point, err := bytesToBN254G2(pointBytes)
	if err != nil {
		return false, err
	}
	return point.IsInSubGroup(), nil
}

// ed25519Order is the prime order L of the ed25519 main subgroup,
// 2^252 + 27742317777372353535851937790883648493.
var ed25519Order, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

// ed25519OrderMinusOne is L-1 as a canonical scalar. Used by the subgroup check
// to compute [L]P as [L-1]P + P, since edwards25519.Scalar cannot represent L
// itself (it would reduce to 0).
var ed25519OrderMinusOne = func() *edwards25519.Scalar {
	s, err := bigIntToEd25519Scalar(new(big.Int).Sub(ed25519Order, big.NewInt(1)))
	if err != nil {
		panic(err) // L-1 is canonical by construction
	}
	return s
}()

// ed25519FieldModulus is p = 2^255 - 19, the ed25519 base field order.
var ed25519FieldModulus = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// reverse32 returns a new slice with the bytes of a (32-byte) coordinate
// reversed, converting between the big-endian on-stack encoding (shared with
// the other ec_ groups) and edwards25519/field's little-endian encoding.
func reverse32(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// bytesToEd25519Field decodes a 32-byte big-endian field element, rejecting
// non-canonical encodings (>= p) as the other ec_ groups do.
func bytesToEd25519Field(b []byte) (*edfield.Element, error) {
	if big := new(big.Int).SetBytes(b); big.Cmp(ed25519FieldModulus) >= 0 {
		return nil, fmt.Errorf("ed25519 coordinate %s larger than modulus", big.String())
	}
	return new(edfield.Element).SetBytes(reverse32(b)) // length already curve-checked by caller
}

// bytesToEd25519Point decodes an uncompressed point: 32 byte big-endian X
// followed by 32 byte big-endian Y, validating that it is on the curve. Like
// the other ec_ groups, points are kept uncompressed so that chained
// operations avoid a per-op decompression (square root).
func bytesToEd25519Point(b []byte) (*edwards25519.Point, error) {
	if len(b) != ed25519PointSize {
		return nil, fmt.Errorf("bad ed25519 point length %d. Expected %d", len(b), ed25519PointSize)
	}
	x, err := bytesToEd25519Field(b[:ed25519fpSize])
	if err != nil {
		return nil, err
	}
	y, err := bytesToEd25519Field(b[ed25519fpSize:])
	if err != nil {
		return nil, err
	}
	// Extended coordinates with Z=1, so T = x*y. SetExtendedCoordinates checks
	// both the curve equation and the T relation.
	t := new(edfield.Element).Multiply(x, y)
	point, err := new(edwards25519.Point).SetExtendedCoordinates(x, y, new(edfield.Element).One(), t)
	if err != nil {
		return nil, fmt.Errorf("invalid ed25519 point: %w", err)
	}
	return point, nil
}

// ed25519PointToBytes encodes a point as uncompressed 32 byte big-endian X
// followed by 32 byte big-endian Y. The single field inversion to recover
// affine coordinates is the only unavoidable per-op cost, matching the gnark
// curves.
func ed25519PointToBytes(point *edwards25519.Point) []byte {
	bigX, bigY, bigZ, _ := point.ExtendedCoordinates()
	zInv := new(edfield.Element).Invert(bigZ)
	var x, y edfield.Element
	x.Multiply(bigX, zInv)
	y.Multiply(bigY, zInv)
	out := make([]byte, ed25519PointSize)
	copy(out[:ed25519fpSize], reverse32(x.Bytes()))
	copy(out[ed25519fpSize:], reverse32(y.Bytes()))
	return out
}

// bigIntToEd25519Scalar reduces a big-endian integer (the on-stack scalar
// convention shared by all ec_ opcodes) modulo L and returns it as a canonical
// edwards25519.Scalar.
func bigIntToEd25519Scalar(k *big.Int) (*edwards25519.Scalar, error) {
	be := new(big.Int).Mod(k, ed25519Order).Bytes() // 0 <= r < L, big-endian, <= 32 bytes
	var le [32]byte
	for i := range be {
		le[len(be)-1-i] = be[i] // reverse to little-endian, leaving high bytes zero
	}
	return new(edwards25519.Scalar).SetCanonicalBytes(le[:])
}

func ed25519Add(aBytes, bBytes []byte) ([]byte, error) {
	a, err := bytesToEd25519Point(aBytes)
	if err != nil {
		return nil, err
	}
	b, err := bytesToEd25519Point(bBytes)
	if err != nil {
		return nil, err
	}
	var res edwards25519.Point
	res.Add(a, b)
	return ed25519PointToBytes(&res), nil
}

// The scalar multiplications below use edwards25519's variable-time routines,
// whose running time depends on the scalar. There is nothing to leak: a
// program, its arguments, and the whole transaction are public, so the scalars
// these opcodes multiply by are public too. They are about 40% faster than the
// constant-time equivalents, and produce identical results. Their costs are set
// from the worst-case scalar rather than a typical one, which BenchmarkEd25519
// measures directly.
func ed25519ScalarMul(aBytes []byte, k *big.Int) ([]byte, error) {
	a, err := bytesToEd25519Point(aBytes)
	if err != nil {
		return nil, err
	}
	s, err := bigIntToEd25519Scalar(k)
	if err != nil {
		return nil, err
	}
	var res edwards25519.Point
	res.VarTimeMultiScalarMult([]*edwards25519.Scalar{s}, []*edwards25519.Point{a})
	return ed25519PointToBytes(&res), nil
}

func ed25519MultiMul(pointBytes, scalarBytes []byte) ([]byte, error) {
	if len(pointBytes)%ed25519PointSize != 0 {
		return nil, fmt.Errorf("bad ed25519 points length %d, not a multiple of %d", len(pointBytes), ed25519PointSize)
	}
	n := len(pointBytes) / ed25519PointSize
	if n == 0 {
		return nil, errEmptyInput // as the other groups do, though the empty sum is the identity
	}
	if len(scalarBytes) != scalarSize*n {
		return nil, fmt.Errorf("bad scalars length %d. Expected %d", len(scalarBytes), scalarSize*n)
	}
	points := make([]*edwards25519.Point, n)
	scalars := make([]*edwards25519.Scalar, n)
	for i := range points {
		var err error
		points[i], err = bytesToEd25519Point(pointBytes[i*ed25519PointSize : (i+1)*ed25519PointSize])
		if err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(scalarBytes[i*scalarSize : (i+1)*scalarSize])
		scalars[i], err = bigIntToEd25519Scalar(k)
		if err != nil {
			return nil, err
		}
	}
	var res edwards25519.Point
	res.VarTimeMultiScalarMult(scalars, points)
	return ed25519PointToBytes(&res), nil
}

// ed25519SubgroupCheck reports whether the point is in the prime-order
// subgroup, i.e. it is torsion-free. P is torsion-free iff [L]P is the
// identity, computed here as [L-1]P + P.
func ed25519SubgroupCheck(pointBytes []byte) (bool, error) {
	point, err := bytesToEd25519Point(pointBytes)
	if err != nil {
		return false, err
	}
	var lp edwards25519.Point
	lp.VarTimeMultiScalarMult([]*edwards25519.Scalar{ed25519OrderMinusOne}, []*edwards25519.Point{point})
	lp.Add(&lp, point)
	return lp.Equal(edwards25519.NewIdentityPoint()) == 1, nil
}

// ed25519MontJ is the J coefficient of curve25519, K*t^2 = s^3 + J*s^2 + s with
// K of 1, the Montgomery curve that edwards25519 is birationally equivalent to.
var ed25519MontJ = new(edfield.Element).Mult32(new(edfield.Element).One(), 486662)

// ed25519MapC is sqrt(-486664), the constant in the birational map from
// curve25519 to edwards25519. RFC 9380 requires the root whose sgn0 is 0, so
// that mapping the edwards25519 base point yields the curve25519 base point.
// SqrtRatio returns exactly that root.
var ed25519MapC = func() *edfield.Element {
	var negJ2 edfield.Element
	negJ2.Mult32(new(edfield.Element).One(), 486664)
	negJ2.Negate(&negJ2)
	c, wasSquare := new(edfield.Element).SqrtRatio(&negJ2, new(edfield.Element).One())
	if wasSquare != 1 {
		panic("edwards25519: -486664 is not square") // it is
	}
	return c
}()

// ed25519MapInput decodes the argument both edwards25519 maps take: a
// big-endian field element below the modulus, which need not be 0-padded, as
// for the other curves.
func ed25519MapInput(fpBytes []byte) (*edfield.Element, error) {
	if len(fpBytes) > ed25519fpSize {
		return nil, fmt.Errorf("bad ed25519 field element length %d. Expected at most %d",
			len(fpBytes), ed25519fpSize)
	}
	padded := make([]byte, ed25519fpSize)
	copy(padded[ed25519fpSize-len(fpBytes):], fpBytes)
	return bytesToEd25519Field(padded)
}

// ed25519MapTo is RFC 9380's map_to_curve_elligator2_edwards25519, followed by
// clearing the cofactor so that the result is always in the prime-order
// subgroup - the guarantee the other groups' maps make as well.
//
// It is map_to_curve, not hash_to_curve. It maps one field element, and does
// not hash. Producing that element from a message (RFC 9380's expand_message
// with a domain separation tag) is the caller's job, as is mapping two elements
// and adding them if the caller needs an output uniform over the group. A
// single mapped element is not uniform.
//
// ec_map_to means "this curve's standard map", SSWU for BLS12-381 and SVDW for
// BN254, and for edwards25519 that is Elligator 2. It is also what this node
// already computes elsewhere, since vrf_verify is
// ECVRF-ED25519-SHA512-Elligator2. Protocols predating RFC 9380 hash to this
// curve by their own maps, and those are deliberately not what this computes. A
// program that wants such a map names it: ED25519_Monero selects the one
// CryptoNote wrote, in ed25519MoneroMapTo below.
//
// Coordinates are carried as fractions rather than divided, so the square root
// and the one inversion needed to encode the result are the only
// exponentiations.
func ed25519MapTo(fpBytes []byte) ([]byte, error) {
	u, err := ed25519MapInput(fpBytes)
	if err != nil {
		return nil, err
	}
	one := new(edfield.Element).One()

	// Elligator 2 onto curve25519, keeping x as the fraction xMn/xMd
	var zuu, xMd, x1n, xMd2, gxd, gx1n edfield.Element
	zuu.Square(u)
	zuu.Add(&zuu, &zuu)      // Z*u^2, the suite's Z being 2
	xMd.Add(&zuu, one)       // 1 + Z*u^2, never 0: -1 is square and Z*u^2 is not
	x1n.Negate(ed25519MontJ) // x1 = -J / (1 + Z*u^2)
	xMd2.Square(&xMd)
	gxd.Multiply(&xMd2, &xMd) // xMd^3, the denominator of g(x1) and g(x2)
	gx1n.Multiply(ed25519MontJ, &zuu)
	gx1n.Multiply(&gx1n, &x1n)
	gx1n.Add(&gx1n, &xMd2)
	gx1n.Multiply(&gx1n, &x1n) // x1n^3 + J*x1n^2*xMd + x1n*xMd^2

	xMn := x1n
	yM, wasSquare := new(edfield.Element).SqrtRatio(&gx1n, &gxd)
	if wasSquare == 1 {
		yM.Negate(yM) // RFC 9380 wants sgn0 of 1 here, where SqrtRatio gives 0
	} else {
		// x2 = Z*u^2*x1, whose g() is Z*u^2*g(x1), and is square when g(x1) is not
		xMn.Multiply(&x1n, &zuu)
		var gx2n edfield.Element
		gx2n.Multiply(&gx1n, &zuu)
		var square int
		if yM, square = new(edfield.Element).SqrtRatio(&gx2n, &gxd); square != 1 {
			return nil, errors.New("ed25519 elligator2: neither candidate was square")
		}
		// and here it wants sgn0 of 0, which is what SqrtRatio returns
	}

	// across the birational map: x = c*xM/yM and y = (xM-1)/(xM+1), with xM
	// still a fraction, so both coordinates come out as fractions too
	var xn, xd, yn, yd, degenerate edfield.Element
	xn.Multiply(&xMn, ed25519MapC)
	xd.Multiply(&xMd, yM)
	yn.Subtract(&xMn, &xMd)
	yd.Add(&xMn, &xMd)
	degenerate.Multiply(&xd, &yd)
	if degenerate.Equal(new(edfield.Element).Zero()) == 1 {
		xn.Zero() // the map sends these to the identity
		xd.One()
		yn.One()
		yd.One()
	}

	// extended coordinates are projective, so the fractions go straight in:
	// X/Z is xn/xd, Y/Z is yn/yd, and the T relation X*Y == Z*T holds
	var X, Y, Z, T edfield.Element
	X.Multiply(&xn, &yd)
	Y.Multiply(&yn, &xd)
	Z.Multiply(&xd, &yd)
	T.Multiply(&xn, &yn)
	var point edwards25519.Point
	if _, err := point.SetExtendedCoordinates(&X, &Y, &Z, &T); err != nil {
		return nil, fmt.Errorf("ed25519 elligator2 left the curve: %w", err)
	}
	point.MultByCofactor(&point) // into the prime-order subgroup
	return ed25519PointToBytes(&point), nil
}

// The constants of the CryptoNote map, all derived from J, which Monero's C
// calls A. Monero stores them as fixed limb arrays in crypto-ops-data.c; naming
// what they are here is what lets the port be read against the original.
//
// The four roots all exist. p is 5 mod 8, so 2 and sqrt(-1) are both
// non-squares, and J*(J+2) is a non-square as well, which leaves 2*J*(J+2) and
// both of +/-sqrt(-1)*J*(J+2) squares. TestEd25519MoneroConstants checks each
// one rather than trusting that sentence.
//
// Which root of each SqrtRatio returns does not matter. The map's last step
// forces the sign of the result to the branch it took, and using the other root
// of -1 swaps the fffb3 and fffb4 branches and their constants together.
var (
	ed25519MontNegJ   = new(edfield.Element).Negate(ed25519MontJ)                 // -A
	ed25519MontNegJSq = new(edfield.Element).Negate(ed25519Squared(ed25519MontJ)) // -A^2
	ed25519SqrtM1     = ed25519MustSqrt(new(edfield.Element).Negate(new(edfield.Element).One()))

	// J*(J+2) and twice it, the values the four roots are roots of
	ed25519MontJJ2 = new(edfield.Element).Multiply(ed25519MontJ,
		new(edfield.Element).Add(ed25519MontJ, new(edfield.Element).Mult32(new(edfield.Element).One(), 2)))
	ed25519MontJJ2x2 = new(edfield.Element).Add(ed25519MontJJ2, ed25519MontJJ2)

	ed25519MoneroFFFB1 = ed25519MustSqrt(new(edfield.Element).Negate(ed25519MontJJ2x2)) // sqrt(-2*A*(A+2))
	ed25519MoneroFFFB2 = ed25519MustSqrt(ed25519MontJJ2x2)                              // sqrt(2*A*(A+2))
	ed25519MoneroFFFB3 = ed25519MustSqrt(new(edfield.Element).Multiply(
		new(edfield.Element).Negate(ed25519SqrtM1), ed25519MontJJ2)) // sqrt(-sqrt(-1)*A*(A+2))
	ed25519MoneroFFFB4 = ed25519MustSqrt(new(edfield.Element).Multiply(
		ed25519SqrtM1, ed25519MontJJ2)) // sqrt(sqrt(-1)*A*(A+2))
)

func ed25519Squared(x *edfield.Element) *edfield.Element {
	return new(edfield.Element).Square(x)
}

// ed25519MustSqrt returns a square root of x, panicking if x has none. Every use
// is on a constant, so a panic here is a bug in this file rather than anything a
// program can cause.
func ed25519MustSqrt(x *edfield.Element) *edfield.Element {
	root, wasSquare := new(edfield.Element).SqrtRatio(x, new(edfield.Element).One())
	if wasSquare != 1 {
		panic("edwards25519: constant is not a square")
	}
	return root
}

// ed25519DivPowM1 returns (u/v)^((p+3)/8), which is a square root of u/v when
// one exists, and sqrt(-1) times one when it does not. It is Monero's
// fe_divpowm1: u*v^3*(u*v^7)^((p-5)/8), which trades the inversion u/v would
// need for a few multiplications, since Pow22523 is x^((p-5)/8) already.
func ed25519DivPowM1(u, v *edfield.Element) *edfield.Element {
	var v3, uv7, t edfield.Element
	v3.Multiply(ed25519Squared(v), v)    // v^3
	uv7.Multiply(ed25519Squared(&v3), v) // v^7
	uv7.Multiply(&uv7, u)                // u*v^7
	t.Pow22523(&uv7)                     // (u*v^7)^((p-5)/8)
	t.Multiply(&t, &v3)
	return t.Multiply(&t, u)
}

// ed25519MoneroMapTo is CryptoNote's ge_fromfe_frombytes_vartime followed by
// ge_mul8, which together are Monero's map to edwards25519: the second half of
// its hash_to_ec, and all of the hash_to_point its own tests name. A program
// composes the whole of hash_to_ec by hashing first, and the argument here is
// the field element that hash produced, big-endian and reduced, exactly as
// ec_map_to takes for every other group.
//
// The point of it is that Monero's key images are I = [x]H_p(P), so a contract
// that cannot compute H_p cannot check a Monero linkable ring signature at all.
//
// It is Elligator 2 as well, over the same curve with the same Z of 2, which is
// nearer to ED25519 than it looks: the two agree on the Montgomery x, and can
// differ only in which square root they take. They do differ, on exactly the
// inputs that reach the negative branch below, and those are half of all
// inputs.  So the results are the same point half the time and negations of
// each other otherwise, and a program that reached for ED25519 instead of this
// would compute the right key image half the time.  The standard map keeps the
// plain name; see the comment on ed25519MapTo.
//
// This is a faithful port, written to be read beside the C rather than to be
// written fresh. The C reaches its common tail with a goto, which here is the
// sign == 0 test after the branches.
//
// The map is not injective and its output is not uniform over the group - the
// non-uniformity is why current Monero calls the wrapper biased_hash_to_ec - so
// everything ed25519MapTo says about map versus hash applies here too.
func ed25519MoneroMapTo(fpBytes []byte) ([]byte, error) {
	u, err := ed25519MapInput(fpBytes)
	if err != nil {
		return nil, err
	}

	zero := new(edfield.Element).Zero()
	isZero := func(e *edfield.Element) bool { return e.Equal(zero) == 1 }

	var v, w, x, z, X edfield.Element
	uu := ed25519Squared(u)
	v.Add(uu, uu) // v = 2*u^2
	w.Add(&v, new(edfield.Element).One())
	x.Add(ed25519Squared(&w), new(edfield.Element).Multiply(ed25519MontNegJSq, &v)) // x = w^2 - A^2*v
	X.Set(ed25519DivPowM1(&w, &x))
	x.Multiply(ed25519Squared(&X), &x) // the candidate root, squared back
	z.Set(ed25519MontNegJ)

	// Which root the candidate is a root of decides both the constant that
	// turns it into the root of what is wanted, and the sign forced below.
	var root *edfield.Element
	sign := 0
	switch {
	case isZero(new(edfield.Element).Subtract(&w, &x)): // x == w
		root = ed25519MoneroFFFB2
	case isZero(new(edfield.Element).Add(&w, &x)): // x == -w
		root = ed25519MoneroFFFB1
	default:
		// w/x was not a square, so x is sqrt(-1) times w, of one sign or other
		x.Multiply(&x, ed25519SqrtM1)
		switch {
		case isZero(new(edfield.Element).Subtract(&w, &x)):
			root = ed25519MoneroFFFB4
		case isZero(new(edfield.Element).Add(&w, &x)):
			root = ed25519MoneroFFFB3
		default:
			// the C asserts this cannot happen. Inputs are attacker
			// controlled, so it is an error here rather than a panic, though
			// no input is known to reach it.
			return nil, errors.New("ed25519 monero map: no branch matched")
		}
		sign = 1
	}
	X.Multiply(&X, root)
	if sign == 0 { // only the square branches scale by u and z by v
		X.Multiply(&X, u)
		z.Multiply(&z, &v) // -A*v
	}
	if X.IsNegative() != sign {
		X.Negate(&X)
	}

	// affine x is X and affine y is (z-w)/(z+w), so extended coordinates take
	// the fraction directly: X*Z over Z, and (z-w) over Z, with X*Y == Z*T
	var Y, Z, T edfield.Element
	Z.Add(&z, &w)
	Y.Subtract(&z, &w)
	if isZero(&Z) {
		// Z is zero only for u^2 == 1/(2*(A-1)) or u^2 == (A-1)/2, and
		// TestEd25519MoneroConstants shows neither is a square, so no input
		// reaches this. Monero, whose check of the curve equation here is a
		// debug-build assert, would carry the degenerate point forward.
		return nil, errors.New("ed25519 monero map: degenerate point")
	}
	T.Multiply(&X, &Y)
	X.Multiply(&X, &Z)

	var point edwards25519.Point
	if _, err := point.SetExtendedCoordinates(&X, &Y, &Z, &T); err != nil {
		return nil, fmt.Errorf("ed25519 monero map left the curve: %w", err)
	}
	point.MultByCofactor(&point) // ge_mul8
	return ed25519PointToBytes(&point), nil
}
