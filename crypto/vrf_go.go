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

// VrfKeygenFromSeed deterministically generates a VRF keypair from 32 bytes of (secret) entropy.
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
	h, err := crypto_vrf_verify(pk[:], proof[:], msg)
	if err != nil {
		// TODO: this method should return an error.
		// fmt.Println("issue verifying:", err)
		return false, out
	}
	copy(out[:], h)
	return true, out
}

func crypto_vrf_verify(pk []byte, proof []byte, msg []byte) ([]byte, error) {
	return crypto_vrf_ietfdraft03_verify(pk, proof, msg)
}

/* Verify a VRF proof (for a given a public key and message) and validate the
 * public key. If verification succeeds, store the VRF output hash in output[].
 * Specified in draft spec section 5.3.
 *
 * For a given public key and message, there are many possible proofs but only
 * one possible output hash.
 */
func crypto_vrf_ietfdraft03_verify(pk []byte, proof []byte, msg []byte) ([]byte, error) {
	// var Y ge25519_p3
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
	ok, err := vrf_verify(Y, proof, msg)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("issue verifying proof")
	}
	// proof to hash
	return crypto_vrf_ietfdraft03_proof_to_hash(proof)
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
	Y_point, x_scalar, truncated_hashed_sk_string, err := sk.expand()
	if err != nil {
		// TODO: this method should return an error.
		// fmt.Println("issue expanding:", err)
		return proof, false
	}

	proof, err = vrf_prove(Y_point, x_scalar, truncated_hashed_sk_string, msg)
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
 * Constant time in everything except alphalen (the length of the message)
 */
func vrf_prove(Y_point *edwards25519.Point, x_scalar *edwards25519.Scalar, trunc_hashed_sk []byte, alpha []byte) (VrfProof, error) {
	var pi VrfProof
	//var h_string, k_scalar, c_scalar []byte
	//	var H_point, Gamma_point, kB_point, kH_point *edwards25519.Point

	h_string, err := _vrf_ietfdraft03_hash_to_curve_elligator2_25519(Y_point, alpha)
	if err != nil {
		return VrfProof{}, err
	}
	//spew.Dump("x_scalar", x_scalar.Bytes())
	H_point := edwards25519.NewIdentityPoint()
	H_point.SetBytes(h_string)
	// fmt.Printf("h string: %x\n", h_string)
	// fmt.Printf("h poitn: %x\n", H_point.Bytes())
	Gamma_point := edwards25519.NewIdentityPoint()
	Gamma_point.ScalarMult(x_scalar, H_point)
	//fmt.Println(h_string)

	/*
		vrf_nonce_generation(k_scalar, truncated_hashed_sk_string, h_string)
		ge25519_scalarmult_base(&kB_point, k_scalar)      // compute k*B
		ge25519_scalarmult(&kH_point, k_scalar, &H_point) // compute k*H
	*/
	k_scalar := vrf_nonce_generation(trunc_hashed_sk, H_point)
	// fmt.Printf("g k_scalar: %x\n", k_scalar.Bytes())
	// fmt.Printf("g h_point: %x\n", H_point.Bytes())
	// fmt.Printf("g trunc_hash: %x\n", trunc_hashed_sk)
	kB_point := edwards25519.NewIdentityPoint()
	kB_point.ScalarBaseMult(k_scalar)
	kH_point := edwards25519.NewIdentityPoint()
	kH_point.ScalarMult(k_scalar, H_point)
	// fmt.Printf("g kB_point: %x\n", kB_point.Bytes())
	// fmt.Printf("g kH_point: %x\n", kH_point.Bytes())

	c_scalar := _vrf_ietfdraft03_hash_points(H_point, Gamma_point, kB_point, kH_point)
	// fmt.Printf("g c_scalar: %x\n", c_scalar)
	s := edwards25519.NewScalar()
	s.MultiplyAdd(c_scalar, x_scalar, k_scalar)

	// output pi
	copy(pi[:], Gamma_point.Bytes())
	copy(pi[32:], c_scalar.Bytes()[:16])
	copy(pi[48:], s.Bytes())
	/*
		// c = ECVRF_hash_points(h, gamma, k*B, k*H)
		_vrf_ietfdraft03_hash_points(c_scalar, &H_point, &Gamma_point, &kB_point, &kH_point)
		memset(c_scalar+16, 0, 16) // zero the remaining 16 bytes of c_scalar

		// output pi
		_vrf_ietfdraft03_point_to_string(pi, &Gamma_point)  // pi[0:32] = point_to_string(Gamma)
		memmove(pi+32, c_scalar, 16)                        // pi[32:48] = c (16 bytes)
		sc25519_muladd(pi+48, c_scalar, x_scalar, k_scalar) // pi[48:80] = s = c*x + k (mod q)
	*/
	return pi, nil
}

/* Hash a message to a curve point using Elligator2.
 * Specified in VRF draft spec section 5.4.1.2.
 * The actual elligator2 implementation is ge25519_from_uniform.
 * Runtime depends only on alphalen (the message length)
 */
func _vrf_ietfdraft03_hash_to_curve_elligator2_25519(Y_point *edwards25519.Point, alpha []byte) ([]byte, error) {
	hs := sha512.New()

	hs.Write([]byte{vrfSuite})
	hs.Write([]byte{1})
	hs.Write(Y_point.Bytes())
	hs.Write(alpha)
	r_string := hs.Sum(nil)
	r_string[31] &= 0x7f // clear sign bit

	/*
	   crypto_hash_sha512_state hs;
	   unsigned char            Y_string[32], r_string[64];

	   _vrf_ietfdraft03_point_to_string(Y_string, Y_point);

	   // r = first 32 bytes of SHA512(suite || 0x01 || Y || alpha)
	   crypto_hash_sha512_init(&hs);
	   crypto_hash_sha512_update(&hs, &SUITE, 1);
	   crypto_hash_sha512_update(&hs, &ONE, 1);
	   crypto_hash_sha512_update(&hs, Y_string, 32);
	   crypto_hash_sha512_update(&hs, alpha, alphalen);
	   crypto_hash_sha512_final(&hs, r_string);

	   r_string[31] &= 0x7f; // clear sign bit
	   ge25519_from_uniform(H_string, r_string); // elligator2
	*/
	h, err := ge25519_from_uniform(r_string)
	return h, err
}

// elligator2
func ge25519_from_uniform(r []byte) ([]byte, error) {
	s := make([]byte, 32)
	var e, negx, rr2, x, x2, x3 *field.Element
	var p3 *edwards25519.Point
	var e_is_minus_1 int
	var x_sign byte

	copy(s, r)
	x_sign = s[31] & 0x80
	s[31] &= 0x7f
	// fmt.Println("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")

	rr2 = &field.Element{}
	rr2.SetBytes(s) // fe25519_frombytes(rr2, s);

	//rr2a := &field.Element{}.One().Mult32
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
	// fmt.Printf("g rr2: %x\n", rr2.Bytes())

	x2 = &field.Element{}
	x2.Multiply(x, x) // fe25519_sq(x2, x);
	x3 = &field.Element{}
	x3.Multiply(x, x2) // fe25519_mul(x3, x, x2);

	e = &field.Element{}
	e.Add(x3, x)               // fe25519_add(e, x3, x);
	x2.Mult32(x2, curve25519A) // fe25519_mul(x2, x2, curve25519_A);
	e.Add(x2, e)               // fe25519_add(e, x2, e);

	e = chi25519(e) // chi25519(e, e);
	// fmt.Printf("g  e1: %x\n", e.Bytes())
	s = e.Bytes() // fe25519_tobytes(s, e);

	e_is_minus_1 = int(s[1] & 1) // e_is_minus_1 = s[1] & 1;
	e_is_not_minus_1 := e_is_minus_1 ^ 1
	negx = (&field.Element{}).Set(x)
	negx.Negate(negx)                   // fe25519_neg(negx, x);
	x.Select(x, negx, e_is_not_minus_1) // fe25519_cmov(x, negx, e_is_minus_1);
	// fmt.Printf("x: %x\n", x.Bytes())
	// fmt.Printf("negx: %x\n", x.Bytes())
	x2.Zero() // fe25519_0(x2);
	// fmt.Printf("curve: %x\n", curve25519AElement.Bytes())
	// fmt.Printf("x2: %x\n", x2.Bytes())
	// fmt.Printf("e_is_minus_1: %+v\n", e_is_minus_1)
	x2.Select(x2, curve25519AElement, e_is_not_minus_1) // fe25519_cmov(x2, curve25519_A, e_is_minus_1);
	x.Subtract(x, x2)                                   // fe25519_sub(x, x, x2);
	// yed = (x-1)/(x+1)
	{
		var one, x_plus_one, x_plus_one_inv, x_minus_one, yed *field.Element
		// fe25519 one;
		// fe25519 x_plus_one;
		// fe25519 x_plus_one_inv;
		// fe25519 x_minus_one;
		// fe25519 yed;

		one = (&field.Element{}).One()                                 // fe25519_1(one);
		x_plus_one = (&field.Element{}).Add(x, one)                    // fe25519_add(x_plus_one, x, one);
		x_minus_one = (&field.Element{}).Subtract(x, one)              // fe25519_sub(x_minus_one, x, one);
		x_plus_one_inv = (&field.Element{}).Invert(x_plus_one)         // fe25519_invert(x_plus_one_inv, x_plus_one);
		yed = (&field.Element{}).Multiply(x_minus_one, x_plus_one_inv) // fe25519_mul(yed, x_minus_one, x_plus_one_inv);
		s = yed.Bytes()                                                // fe25519_tobytes(s, yed);
	}

	// recover x
	s[31] |= x_sign

	p3 = &edwards25519.Point{}
	_, err := p3.SetBytes(s) // ge25519_frombytes(&p3, s) != 0
	if err != nil {
		// fmt.Printf("issue setting bytes: %x - %v\n", s, err)
		return nil, err
	}

	// // multiply by the cofactor
	p3.MultByCofactor(p3)
	// ge25519_p3_dbl(&p1, &p3);
	// ge25519_p1p1_to_p2(&p2, &p1);
	// ge25519_p2_dbl(&p1, &p2);
	// ge25519_p1p1_to_p2(&p2, &p1);
	// ge25519_p2_dbl(&p1, &p2);
	// ge25519_p1p1_to_p3(&p3, &p1);

	s = p3.Bytes() // ge25519_p3_tobytes(s, &p3);
	// fmt.Printf("g elligator 2: %x\n", s)
	return s, nil
}

func vrf_nonce_generation(trunc_hashed_sk []byte, H_point *edwards25519.Point) *edwards25519.Scalar {
	result := edwards25519.NewScalar()

	hs := sha512.New()
	hs.Write(trunc_hashed_sk)
	hs.Write(H_point.Bytes())
	k_string := hs.Sum(nil)[:64]
	result.SetUniformBytes(k_string)
	// fmt.Printf("g k_string: %x\n", k_string)
	// fmt.Printf("g k_string2: %x\n", result.Bytes())

	return result
}

/* Subroutine specified in draft spec section 5.4.3.
 * Hashes four points to a 16-byte string.
 * Constant time. */
func _vrf_ietfdraft03_hash_points(P1, P2, P3, P4 *edwards25519.Point) *edwards25519.Scalar {
	result := make([]byte, 32)
	var str [2 + (32 * 4)]byte

	str[0] = vrfSuite
	str[1] = 0x02
	copy(str[2+(32*0):], P1.Bytes())
	copy(str[2+(32*1):], P2.Bytes())
	copy(str[2+(32*2):], P3.Bytes())
	copy(str[2+(32*3):], P4.Bytes())
	h := sha512.New()
	//var c1 [32]byte
	// fmt.Printf("gPN %x\n", P4.Bytes())
	h.Write(str[:])
	sum := h.Sum(nil)
	// fmt.Printf("g sum %x\n", sum)

	copy(result[:], sum[:16])
	// sum := h.Sum(str[:])
	// fmt.Println("sum:", sum)
	// result.SetBytes(c1[:])
	// result.SetBytes(c1[:])
	/*
	   unsigned char str[2r32*4], c1[64];

	   str[0] = SUITE;
	   str[1] = TWO;
	   _vrf_ietfdraft03_point_to_string(str+2+32*0, P1);
	   _vrf_ietfdraft03_point_to_string(str+2+32*1, P2);
	   _vrf_ietfdraft03_point_to_string(str+2+32*2, P3);
	   _vrf_ietfdraft03_point_to_string(str+2+32*3, P4);
	   crypto_hash_sha512(c1, str, sizeof str);
	   memmove(c, c1, 16);
	   sodium_memzero(c1, 64);
	*/
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
func vrf_verify(Y *edwards25519.Point, pi []byte, alpha []byte) (bool, error) {
	// // Note: c fits in 16 bytes, but ge25519_scalarmult expects a 32-byte scalar.
	//  // Similarly, s_scalar fits in 32 bytes but sc25519_reduce takes in 64 bytes.
	// unsigned char h_string[32], c_scalar[32], s_scalar[64], cprime[16];

	var H_point, U_point, V_point *edwards25519.Point // ge25519_p3     H_point, Gamma_point, U_point, V_point, tmp_p3_point;
	var tmp1, tmp2 *edwards25519.Point
	// ge25519_p1p1   tmp_p1p1_point;
	// ge25519_cached tmp_cached_point;

	Gamma_point, c_scalar, s_scalar, err := _vrf_ietfdraft03_decode_proof(pi) // _vrf_ietfdraft03_decode_proof(&Gamma_point, c_scalar, s_scalar, pi) != 0

	// // vrf_decode_proof writes to the first 16 bytes of c_scalar; we zero the
	// // second 16 bytes ourselves, as ge25519_scalarmult expects a 32-byte scalar.
	// memset(c_scalar+16, 0, 16);

	// // vrf_decode_proof sets only the first 32 bytes of s_scalar; we zero the
	// // second 32 bytes ourselves, as sc25519_reduce expects a 64-byte scalar.
	// // Reducing the scalar s mod q ensures the high order bit of s is 0, which
	// // ref10's scalarmult functions require.
	// memset(s_scalar+32, 0, 32);
	// sc25519_reduce(s_scalar);

	_ = s_scalar // TODO

	h_string, err := _vrf_ietfdraft03_hash_to_curve_elligator2_25519(Y, alpha)
	if err != nil {
		return false, err
	}
	H_point = &edwards25519.Point{}
	H_point.SetBytes(h_string[:]) // ge25519_frombytes(&H_point, h_string);

	// // calculate U = s*B - c*Y
	tmp1 = &edwards25519.Point{}
	// SetBytes needs 32 bytes while c_scalar is only 16 bytes long.
	c_scalar_bytes := make([]byte, 64)
	copy(c_scalar_bytes, c_scalar)
	c := edwards25519.NewScalar()
	c.SetUniformBytes(c_scalar_bytes)
	tmp1.ScalarMult(c, Y)
	tmp2 = (&edwards25519.Point{}).Set(tmp1)
	s := edwards25519.NewScalar()
	s_scalar_bytes := make([]byte, 64)
	copy(s_scalar_bytes, s_scalar)
	s.SetUniformBytes(s_scalar_bytes)
	tmp1.ScalarBaseMult(s)
	U_point = &edwards25519.Point{}
	U_point.Subtract(tmp1, tmp2)

	// // calculate V = s*H -  c*Gamma
	tmp1 = &edwards25519.Point{}
	tmp1.ScalarMult(s, H_point)
	tmp2 = &edwards25519.Point{}
	tmp2.ScalarMult(c, Gamma_point)
	V_point = &edwards25519.Point{}
	V_point.Subtract(tmp1, tmp2)

	cprime := _vrf_ietfdraft03_hash_points(H_point, Gamma_point, U_point, V_point) // _vrf_ietfdraft03_hash_points(cprime, &H_point, &Gamma_point, &U_point, &V_point);

	cmp := subtle.ConstantTimeCompare(c_scalar[:], cprime.Bytes()) // return crypto_verify_16(c_scalar, cprime);
	return cmp == 1, nil
}

/* Convert a VRF proof pi into a VRF output hash beta per draft spec section 5.2.
 * This function does not verify the proof! For an untrusted proof, instead call
 * crypto_vrf_ietfdraft03_verify, which will output the hash if verification
 * succeeds.
 */
func crypto_vrf_ietfdraft03_proof_to_hash(pi []byte) ([]byte, error) {
	var hash_input [34]byte // unsigned char hash_input[2+32];
	Gamma_point, _, _, err := _vrf_ietfdraft03_decode_proof(pi)
	if err != nil {
		return nil, err
	}
	// beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma))
	hash_input[0] = vrfSuite
	hash_input[1] = 0x03
	Gamma_point.MultByCofactor(Gamma_point)
	copy(hash_input[2:], Gamma_point.Bytes())
	h := sha512.New()
	h.Write(hash_input[:])
	return h.Sum(nil), nil
}

/* Decode an 80-byte proof pi into a point gamma, a 16-byte scalar c, and a
 * 32-byte scalar s, as specified in IETF draft section 5.4.4.
 * Returns 0 on success, nonzero on failure.
 */
func _vrf_ietfdraft03_decode_proof(pi []byte) (gamma *edwards25519.Point, c []byte, s []byte, err error) {
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
