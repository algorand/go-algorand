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

package crypto

import (
	"crypto/sha512"
	"crypto/subtle"
	"fmt"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

const (
	vrfSuite = 0x04 // ECVRF-ED25519-SHA512-Elligator2
)

// VrfKeygenFromSeedGo deterministically generates a VRF keypair from 32 bytes of (secret) entropy.
func VrfKeygenFromSeedGo(seed [32]byte) (VrfPubkey, VrfPrivkey) {
	var pk VrfPubkey
	var sk VrfPrivkey
	h := sha512.New()
	h.Write(seed[:])
	hSum := h.Sum(nil)
	copy(sk[:], hSum[:32])
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	p := edwards25519.NewScalar()
	skBytes := make([]byte, 64)
	copy(skBytes, sk[:32])
	p.SetUniformBytes(skBytes)
	A := edwards25519.NewIdentityPoint().ScalarBaseMult(p)
	copy(pk[:], A.Bytes())
	copy(sk[:], seed[:])
	copy(sk[32:], pk[:])
	return pk, sk
}

func (pk VrfPubkey) verifyBytesGo(proof VrfProof, msg []byte) (bool, VrfOutput) {
	var out VrfOutput
	h, err := vrfVerifyAndHash(pk[:], proof[:], msg)
	if err != nil {
		// TODO: this method should probably return an error.
		// fmt.Println("issue verifying:", err)
		return false, out
	}
	copy(out[:], h)
	return true, out
}

/* Verify a VRF proof (for a given a public key and message) and validate the
 * public key. If verification succeeds, store the VRF output hash in output[].
 * Specified in draft spec section 5.3.
 *
 * For a given public key and message, there are many possible proofs but only
 * one possible output hash.
 */
func vrfVerifyAndHash(pk []byte, proof []byte, msg []byte) ([]byte, error) {
	Y := &edwards25519.Point{}
	// validate key
	if _, err := Y.SetBytes(pk); err != nil {
		return nil, err
	}
	isSmallOrder := (&edwards25519.Point{}).MultByCofactor(Y).Equal(edwards25519.NewIdentityPoint()) == 1
	if isSmallOrder {
		return nil, fmt.Errorf("expected key to have small order")
	}
	// vrf_verify
	ok, err := vrfVerify(Y, proof, msg)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("issue verifying proof")
	}
	// proof to hash
	return cryptoVrfIetfdraft03ProofToHash(proof)
}

/* Utility function to convert a "secret key" (32-byte seed || 32-byte PK)
 * into the public point Y, the private saclar x, and truncated hash of the
 * seed to be used later in nonce generation.
 * Return 0 on success, -1 on failure decoding the public point Y.
 */
func (sk VrfPrivkey) expand() (*edwards25519.Point, *edwards25519.Scalar, []byte, error) {
	var tmp [64]byte
	h := sha512.New()
	h.Write(sk[:32])
	hSum := h.Sum(nil)
	copy(tmp[:], hSum[:64])
	xScaler := edwards25519.NewScalar()
	tmpBytes := make([]byte, 64)
	copy(tmpBytes, tmp[:32])
	xScaler.SetBytesWithClamping(tmp[:32])

	truncatedHashedSKString := tmp[32:]
	Y := edwards25519.NewIdentityPoint()
	Y.SetBytes(sk[32:])
	return Y, xScaler, truncatedHashedSKString, nil
}

func (sk VrfPrivkey) proveBytesGo(msg []byte) (proof VrfProof, ok bool) {
	// inlined vrf_expand_sk
	Y, xScalar, truncatedHashedSkString, err := sk.expand()
	if err != nil {
		// TODO: this method should return an error.
		// fmt.Println("issue expanding:", err)
		return proof, false
	}
	proof, err = pureGoVrfProve(Y, xScalar, truncatedHashedSkString, msg)
	if err != nil {
		// TODO: this method should return an error.
		// fmt.Println("issue proving:", err)
		return proof, false
	}
	return proof, err == nil
}

/* Construct a proof for a message alpha per draft spec section 5.1.
 * Takes in a secret scalar x, a public point Y, and a secret string
 * truncated_hashed_sk that is used in nonce generation.
 * These are computed from the secret key using the expand_sk function.
 * Constant time in everything except the length of alpha.
 */
func pureGoVrfProve(Y *edwards25519.Point, xScalar *edwards25519.Scalar, truncHashedSk []byte, alpha []byte) (VrfProof, error) {
	var pi VrfProof
	H, err := vrfHashToCurveElligator225519(Y, alpha)
	if err != nil {
		return VrfProof{}, err
	}
	Gamma := edwards25519.NewIdentityPoint()
	Gamma.ScalarMult(xScalar, H)

	kScalar := vrfNonceGeneration(truncHashedSk, H)
	kB := edwards25519.NewIdentityPoint()
	kB.ScalarBaseMult(kScalar)
	kH := edwards25519.NewIdentityPoint()
	kH.ScalarMult(kScalar, H)

	cScalar := vrfHashPoints(H, Gamma, kB, kH)
	s := edwards25519.NewScalar()
	s.MultiplyAdd(cScalar, xScalar, kScalar)

	// output pi
	copy(pi[:], Gamma.Bytes())
	copy(pi[32:], cScalar.Bytes()[:16])
	copy(pi[48:], s.Bytes())
	return pi, nil
}

/* Hash a message to a curve point using Elligator2.
 * Specified in VRF draft spec section 5.4.1.2.
 * The actual elligator2 implementation is ge25519_from_uniform.
 * Runtime depends only on alphalen (the message length)
 */
func vrfHashToCurveElligator225519(Y *edwards25519.Point, alpha []byte) (*edwards25519.Point, error) {
	hs := sha512.New()

	hs.Write([]byte{vrfSuite})
	hs.Write([]byte{1})
	hs.Write(Y.Bytes())
	hs.Write(alpha)
	rString := hs.Sum(nil)
	rString[31] &= 0x7f // clear sign bit

	hBytes, err := ge25519FromUniform(rString)
	if err != nil {
		return nil, err
	}
	result := &edwards25519.Point{}
	result.SetBytes(hBytes[:]) // ge25519_frombytes(&H_point, h_string);
	return result, nil
}

// elligator2
func ge25519FromUniform(r []byte) ([]byte, error) {
	s := make([]byte, 32)
	var e, negx, rr2, x, x2, x3 *field.Element
	var p3 *edwards25519.Point
	var eIsMinus1 int
	var xSign byte

	copy(s, r)
	xSign = s[31] & 0x80
	s[31] &= 0x7f

	rr2 = &field.Element{}
	rr2.SetBytes(s) // fe25519_frombytes(rr2, s);

	// elligator
	rr2.Square(rr2) // fe25519_sq2(rr2, rr2);
	rr2.Add(rr2, rr2)
	rr2Bytes := rr2.Bytes()
	rr2Bytes[0]++
	rr2.SetBytes(rr2Bytes) // rr2[0]++;
	rr2.Invert(rr2)        // fe25519_invert(rr2, rr2);

	x = &field.Element{}

	const curve25519A = 486662
	curve25519AElement := (&field.Element{}).One().Mult32((&field.Element{}).One(), curve25519A)

	x.Mult32(rr2, curve25519A) // fe25519_mul(x, curve25519_A, rr2);
	x.Negate(x)                // fe25519_neg(x, x);

	x2 = &field.Element{}
	x2.Multiply(x, x) // fe25519_sq(x2, x);
	x3 = &field.Element{}
	x3.Multiply(x, x2) // fe25519_mul(x3, x, x2);

	e = &field.Element{}
	e.Add(x3, x)               // fe25519_add(e, x3, x);
	x2.Mult32(x2, curve25519A) // fe25519_mul(x2, x2, curve25519_A);
	e.Add(x2, e)               // fe25519_add(e, x2, e);

	e = chi25519(e) // chi25519(e, e);
	s = e.Bytes()   // fe25519_tobytes(s, e);

	eIsMinus1 = int(s[1] & 1) // e_is_minus_1 = s[1] & 1;
	eIsNotMinus1 := eIsMinus1 ^ 1
	negx = (&field.Element{}).Set(x)
	negx.Negate(negx)                               // fe25519_neg(negx, x);
	x.Select(x, negx, eIsNotMinus1)                 // fe25519_cmov(x, negx, e_is_minus_1);
	x2.Zero()                                       // fe25519_0(x2);
	x2.Select(x2, curve25519AElement, eIsNotMinus1) // fe25519_cmov(x2, curve25519_A, e_is_minus_1);
	x.Subtract(x, x2)                               // fe25519_sub(x, x, x2);
	// yed = (x-1)/(x+1)
	{
		var one, xPlusOne, xPlusOneInv, xMinusOne, yed *field.Element

		one = (&field.Element{}).One()                            // fe25519_1(one);
		xPlusOne = (&field.Element{}).Add(x, one)                 // fe25519_add(x_plus_one, x, one);
		xMinusOne = (&field.Element{}).Subtract(x, one)           // fe25519_sub(x_minus_one, x, one);
		xPlusOneInv = (&field.Element{}).Invert(xPlusOne)         // fe25519_invert(x_plus_one_inv, x_plus_one);
		yed = (&field.Element{}).Multiply(xMinusOne, xPlusOneInv) // fe25519_mul(yed, x_minus_one, x_plus_one_inv);
		s = yed.Bytes()                                           // fe25519_tobytes(s, yed);
	}

	// recover x
	s[31] |= xSign

	p3 = &edwards25519.Point{}
	_, err := p3.SetBytes(s) // ge25519_frombytes(&p3, s) != 0
	if err != nil {
		// fmt.Printf("issue setting bytes: %x - %v\n", s, err)
		return nil, err
	}

	// // multiply by the cofactor
	p3.MultByCofactor(p3)

	s = p3.Bytes() // ge25519_p3_tobytes(s, &p3);
	return s, nil
}

func vrfNonceGeneration(truncHashedSk []byte, H *edwards25519.Point) *edwards25519.Scalar {
	result := edwards25519.NewScalar()

	hs := sha512.New()
	hs.Write(truncHashedSk)
	hs.Write(H.Bytes())
	kString := hs.Sum(nil)[:64]
	result.SetUniformBytes(kString)

	return result
}

/* Subroutine specified in draft spec section 5.4.3.
 * Hashes four points to a 16-byte string.
 * Constant time. */
func vrfHashPoints(P1, P2, P3, P4 *edwards25519.Point) *edwards25519.Scalar {
	result := make([]byte, 32)
	var str [2 + (32 * 4)]byte

	str[0] = vrfSuite
	str[1] = 0x02
	copy(str[2+(32*0):], P1.Bytes())
	copy(str[2+(32*1):], P2.Bytes())
	copy(str[2+(32*2):], P3.Bytes())
	copy(str[2+(32*3):], P4.Bytes())
	h := sha512.New()
	h.Write(str[:])
	sum := h.Sum(nil)

	copy(result[:], sum[:16])
	r := edwards25519.NewScalar()
	r.SetCanonicalBytes(result)
	return r

}

func chi25519(z *field.Element) *field.Element {
	out := &field.Element{}
	out.Set(z)

	var t0, t1, t2, t3 *field.Element // fe25519 t0, t1, t2, t3;
	var i int                         // int     i;

	t0 = &field.Element{}
	t1 = &field.Element{}
	t2 = &field.Element{}
	t3 = &field.Element{}

	t0.Square(z)        // fe25519_sq(t0, z);
	t1.Multiply(t0, z)  // fe25519_mul(t1, t0, z);
	t0.Square(t1)       // fe25519_sq(t0, t1);
	t2.Square(t0)       // fe25519_sq(t2, t0);
	t2.Square(t2)       // fe25519_sq(t2, t2);
	t2.Multiply(t2, t0) // fe25519_mul(t2, t2, t0);
	t1.Multiply(t2, z)  // fe25519_mul(t1, t2, z);
	t2.Square(t1)       // fe25519_sq(t2, t1);

	for i = 1; i < 5; i++ {
		t2.Square(t2) // fe25519_sq(t2, t2);
	}
	t1.Multiply(t2, t1) // fe25519_mul(t1, t2, t1);
	t2.Square(t1)       // fe25519_sq(t2, t1);
	for i = 1; i < 10; i++ {
		t2.Square(t2) //     fe25519_sq(t2, t2);
	}
	t2.Multiply(t2, t1) // fe25519_mul(t2, t2, t1);
	t3.Square(t2)       // fe25519_sq(t3, t2);
	// fmt.Printf("g t2b: %x\n", t2.Bytes())
	// fmt.Printf("g t3b: %x\n", t3.Bytes())
	for i = 1; i < 20; i++ {
		t3.Square(t3) //     fe25519_sq(t3, t3);
	}
	t2.Multiply(t3, t2) // fe25519_mul(t2, t3, t2);
	t2.Square(t2)       // fe25519_sq(t2, t2);
	for i = 1; i < 10; i++ {
		t2.Square(t2) //     fe25519_sq(t2, t2);
	}
	t1.Multiply(t2, t1) // fe25519_mul(t1, t2, t1);
	t2.Square(t1)       // fe25519_sq(t2, t1);
	// fmt.Printf("g t2c: %x\n", t2.Bytes())
	// fmt.Printf("g t3c: %x\n", t3.Bytes())
	// fmt.Printf("g t1 50: %x\n", t1.Bytes())
	// fmt.Printf("g t2 50: %x\n", t2.Bytes())
	// fmt.Printf("g t3 50: %x\n", t3.Bytes())

	for i = 1; i < 50; i++ {
		t2.Square(t2) //     fe25519_sq(t2, t2);
	}
	t2.Multiply(t2, t1) // fe25519_mul(t2, t2, t1);
	t3.Square(t2)       // fe25519_sq(t3, t2);
	for i = 1; i < 100; i++ {
		t3.Square(t3) //     fe25519_sq(t3, t3);
	}
	t2.Multiply(t3, t2) // fe25519_mul(t2, t3, t2);
	t2.Square(t2)       // fe25519_sq(t2, t2);
	for i = 1; i < 50; i++ {
		t2.Square(t2) //     fe25519_sq(t2, t2);
	}
	t1.Multiply(t2, t1) // fe25519_mul(t1, t2, t1);
	t1.Square(t1)       // fe25519_sq(t1, t1);
	for i = 1; i < 4; i++ {
		t1.Square(t1) //     fe25519_sq(t1, t1);
	}
	out.Multiply(t1, t0) // fe25519_mul(out, t1, t0);

	return out
}

/* Verify a proof per draft section 5.3.
 * We assume Y_point has passed public key validation already.
 * Assuming verification succeeds, runtime does not depend on the message alpha
 * (but does depend on its length alphalen)
 */
func vrfVerify(Y *edwards25519.Point, pi []byte, alpha []byte) (bool, error) {
	var U, V *edwards25519.Point // ge25519_p3     H_point, Gamma_point, U_point, V_point, tmp_p3_point;
	var tmp1, tmp2 *edwards25519.Point

	Gamma, cScalar, sScalar, err := vrfIetfdraft03DecodeProof(pi) // _vrf_ietfdraft03_decode_proof(&Gamma_point, c_scalar, s_scalar, pi) != 0
	if err != nil {
		return false, err
	}
	H, err := vrfHashToCurveElligator225519(Y, alpha)
	if err != nil {
		return false, err
	}

	// // calculate U = s*B - c*Y
	tmp1 = &edwards25519.Point{}
	// SetBytes needs 32 bytes while c_scalar is only 16 bytes long.
	cScalarBytes := make([]byte, 64)
	copy(cScalarBytes, cScalar)
	c := edwards25519.NewScalar()
	c.SetUniformBytes(cScalarBytes)
	tmp1.ScalarMult(c, Y)
	tmp2 = (&edwards25519.Point{}).Set(tmp1)
	s := edwards25519.NewScalar()
	sScalarBytes := make([]byte, 64)
	copy(sScalarBytes, sScalar)
	s.SetUniformBytes(sScalarBytes)
	tmp1.ScalarBaseMult(s)
	U = &edwards25519.Point{}
	U.Subtract(tmp1, tmp2)

	// // calculate V = s*H -  c*Gamma
	tmp1 = &edwards25519.Point{}
	tmp1.ScalarMult(s, H)
	tmp2 = &edwards25519.Point{}
	tmp2.ScalarMult(c, Gamma)
	V = &edwards25519.Point{}
	V.Subtract(tmp1, tmp2)

	cprime := vrfHashPoints(H, Gamma, U, V) // _vrf_ietfdraft03_hash_points(cprime, &H_point, &Gamma_point, &U_point, &V_point);

	cmp := subtle.ConstantTimeCompare(cScalar[:], cprime.Bytes()) // return crypto_verify_16(c_scalar, cprime);
	return cmp == 1, nil
}

/* Convert a VRF proof pi into a VRF output hash beta per draft spec section 5.2.
 * This function does not verify the proof! For an untrusted proof, instead call
 * crypto_vrf_ietfdraft03_verify, which will output the hash if verification
 * succeeds.
 */
func cryptoVrfIetfdraft03ProofToHash(pi []byte) ([]byte, error) {
	var hashInput [34]byte // unsigned char hash_input[2+32];
	Gamma, _, _, err := vrfIetfdraft03DecodeProof(pi)
	if err != nil {
		return nil, err
	}
	// beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma))
	hashInput[0] = vrfSuite
	hashInput[1] = 0x03
	Gamma.MultByCofactor(Gamma)
	copy(hashInput[2:], Gamma.Bytes())
	h := sha512.New()
	h.Write(hashInput[:])
	return h.Sum(nil), nil
}

/* Decode an 80-byte proof pi into a point gamma, a 16-byte scalar c, and a
 * 32-byte scalar s, as specified in IETF draft section 5.4.4.
 * Returns 0 on success, nonzero on failure.
 */
func vrfIetfdraft03DecodeProof(pi []byte) (gamma *edwards25519.Point, c []byte, s []byte, err error) {
	if len(pi) != 80 {
		return nil, nil, nil, fmt.Errorf("unexpected length of pi (must be 80)")
	}
	/* gamma = decode_point(pi[0:32]) */
	gamma = &edwards25519.Point{}
	gamma.SetBytes(pi[:32])
	c = make([]byte, 32)
	s = make([]byte, 32)
	copy(c[:], pi[32:48]) // c = pi[32:48]
	copy(s[:], pi[48:80]) // s = pi[48:80]
	return gamma, c, s, nil
}
