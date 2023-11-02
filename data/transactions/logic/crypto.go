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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/secp256k1"
	"github.com/algorand/go-algorand/protocol"
	"golang.org/x/crypto/sha3"
)

func opSHA256(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	hash := sha256.Sum256(cx.Stack[last].Bytes)
	cx.Stack[last].Bytes = hash[:]
	return nil
}

// The NIST SHA3-256 is implemented for compatibility with ICON
func opSHA3_256(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	hash := sha3.Sum256(cx.Stack[last].Bytes)
	cx.Stack[last].Bytes = hash[:]
	return nil
}

// The Keccak256 variant of SHA-3 is implemented for compatibility with Ethereum
func opKeccak256(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(cx.Stack[last].Bytes)
	hv := make([]byte, 0, hasher.Size())
	hv = hasher.Sum(hv)
	cx.Stack[last].Bytes = hv
	return nil
}

// This is the hash commonly used in Algorand in crypto/util.go Hash()
//
// It is explicitly implemented here in terms of the specific hash for
// stability and portability in case the rest of Algorand ever moves
// to a different default hash. For stability of this language, at
// that time a new opcode should be made with the new hash.
func opSHA512_256(cx *EvalContext) error {
	last := len(cx.Stack) - 1
	hash := sha512.Sum512_256(cx.Stack[last].Bytes)
	cx.Stack[last].Bytes = hash[:]
	return nil
}

// Msg is data meant to be signed and then verified with the
// ed25519verify opcode.
type Msg struct {
	_struct     struct{}      `codec:",omitempty,omitemptyarray"`
	ProgramHash crypto.Digest `codec:"p"`
	Data        []byte        `codec:"d"`
}

// ToBeHashed implements crypto.Hashable
func (msg Msg) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.ProgramData, append(msg.ProgramHash[:], msg.Data...)
}

// programHash lets us lazily compute H(cx.program)
func (cx *EvalContext) programHash() crypto.Digest {
	if cx.programHashCached == (crypto.Digest{}) {
		cx.programHashCached = crypto.HashObj(Program(cx.program))
	}
	return cx.programHashCached
}

func opEd25519Verify(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // index of PK
	prev := last - 1          // index of signature
	pprev := prev - 1         // index of data

	var sv crypto.SignatureVerifier
	if len(cx.Stack[last].Bytes) != len(sv) {
		return errors.New("invalid public key")
	}
	copy(sv[:], cx.Stack[last].Bytes)

	var sig crypto.Signature
	if len(cx.Stack[prev].Bytes) != len(sig) {
		return errors.New("invalid signature")
	}
	copy(sig[:], cx.Stack[prev].Bytes)

	msg := Msg{ProgramHash: cx.programHash(), Data: cx.Stack[pprev].Bytes}
	cx.Stack[pprev] = boolToSV(sv.Verify(msg, sig))
	cx.Stack = cx.Stack[:prev]
	return nil
}

func opEd25519VerifyBare(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // index of PK
	prev := last - 1          // index of signature
	pprev := prev - 1         // index of data

	var sv crypto.SignatureVerifier
	if len(cx.Stack[last].Bytes) != len(sv) {
		return errors.New("invalid public key")
	}
	copy(sv[:], cx.Stack[last].Bytes)

	var sig crypto.Signature
	if len(cx.Stack[prev].Bytes) != len(sig) {
		return errors.New("invalid signature")
	}
	copy(sig[:], cx.Stack[prev].Bytes)

	cx.Stack[pprev] = boolToSV(sv.VerifyBytes(cx.Stack[pprev].Bytes, sig))
	cx.Stack = cx.Stack[:prev]
	return nil
}

func leadingZeros(size int, b *big.Int) ([]byte, error) {
	byteLength := (b.BitLen() + 7) / 8
	if size < byteLength {
		return nil, fmt.Errorf("insufficient buffer size: %d < %d", size, byteLength)
	}
	buf := make([]byte, size)
	b.FillBytes(buf)
	return buf, nil
}

var ecdsaVerifyCosts = []int{
	Secp256k1: 1700,
	Secp256r1: 2500,
}

var secp256r1 = elliptic.P256()

func opEcdsaVerify(cx *EvalContext) error {
	ecdsaCurve := EcdsaCurve(cx.program[cx.pc+1])
	fs, ok := ecdsaCurveSpecByField(ecdsaCurve)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid curve %d", ecdsaCurve)
	}

	if fs.field != Secp256k1 && fs.field != Secp256r1 {
		return fmt.Errorf("unsupported curve %d", fs.field)
	}

	last := len(cx.Stack) - 1 // index of PK y
	prev := last - 1          // index of PK x
	pprev := prev - 1         // index of signature s
	fourth := pprev - 1       // index of signature r
	fifth := fourth - 1       // index of data

	pkY := cx.Stack[last].Bytes
	pkX := cx.Stack[prev].Bytes
	sigS := cx.Stack[pprev].Bytes
	sigR := cx.Stack[fourth].Bytes
	msg := cx.Stack[fifth].Bytes

	if len(msg) != 32 {
		return fmt.Errorf("the signed data must be 32 bytes long, not %d", len(msg))
	}

	x := new(big.Int).SetBytes(pkX)
	y := new(big.Int).SetBytes(pkY)

	var result bool
	if fs.field == Secp256k1 {
		signature := make([]byte, 0, len(sigR)+len(sigS))
		signature = append(signature, sigR...)
		signature = append(signature, sigS...)

		pubkey := secp256k1.S256().Marshal(x, y)
		result = secp256k1.VerifySignature(pubkey, msg, signature)
	} else if fs.field == Secp256r1 {
		if !cx.Proto.EnablePrecheckECDSACurve || secp256r1.IsOnCurve(x, y) {
			pubkey := ecdsa.PublicKey{
				Curve: secp256r1,
				X:     x,
				Y:     y,
			}
			r := new(big.Int).SetBytes(sigR)
			s := new(big.Int).SetBytes(sigS)
			result = ecdsa.Verify(&pubkey, msg, r, s)
		}
	}

	cx.Stack[fifth] = boolToSV(result)
	cx.Stack = cx.Stack[:fourth]
	return nil
}

var ecdsaDecompressCosts = []int{
	Secp256k1: 650,
	Secp256r1: 2400,
}

func opEcdsaPkDecompress(cx *EvalContext) error {
	ecdsaCurve := EcdsaCurve(cx.program[cx.pc+1])
	fs, ok := ecdsaCurveSpecByField(ecdsaCurve)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid curve %d", ecdsaCurve)
	}

	if fs.field != Secp256k1 && fs.field != Secp256r1 {
		return fmt.Errorf("unsupported curve %d", fs.field)
	}

	last := len(cx.Stack) - 1 // compressed PK

	pubkey := cx.Stack[last].Bytes
	var x, y *big.Int
	if fs.field == Secp256k1 {
		x, y = secp256k1.DecompressPubkey(pubkey)
		if x == nil {
			return fmt.Errorf("invalid pubkey")
		}
	} else if fs.field == Secp256r1 {
		x, y = elliptic.UnmarshalCompressed(elliptic.P256(), pubkey)
		if x == nil {
			return fmt.Errorf("invalid compressed pubkey")
		}
	}

	var err error
	cx.Stack[last].Uint = 0
	cx.Stack[last].Bytes, err = leadingZeros(32, x)
	if err != nil {
		return fmt.Errorf("x component zeroing failed: %w", err)
	}

	var sv stackValue
	sv.Bytes, err = leadingZeros(32, y)
	if err != nil {
		return fmt.Errorf("y component zeroing failed: %w", err)
	}

	cx.Stack = append(cx.Stack, sv)
	return nil
}

func opEcdsaPkRecover(cx *EvalContext) error {
	ecdsaCurve := EcdsaCurve(cx.program[cx.pc+1])
	fs, ok := ecdsaCurveSpecByField(ecdsaCurve)
	if !ok || fs.version > cx.version {
		return fmt.Errorf("invalid curve %d", ecdsaCurve)
	}

	if fs.field != Secp256k1 {
		return fmt.Errorf("unsupported curve %d", fs.field)
	}

	last := len(cx.Stack) - 1 // index of signature s
	prev := last - 1          // index of signature r
	pprev := prev - 1         // index of recovery id
	fourth := pprev - 1       // index of data

	sigS := cx.Stack[last].Bytes
	sigR := cx.Stack[prev].Bytes
	recid := cx.Stack[pprev].Uint
	msg := cx.Stack[fourth].Bytes

	if recid > 3 {
		return fmt.Errorf("invalid recovery id: %d", recid)
	}

	signature := make([]byte, 0, len(sigR)+len(sigS)+1)
	signature = append(signature, sigR...)
	signature = append(signature, sigS...)
	signature = append(signature, uint8(recid))

	pk, err := secp256k1.RecoverPubkey(msg, signature)
	if err != nil {
		return fmt.Errorf("pubkey recover failed: %s", err.Error())
	}
	x, y := secp256k1.S256().Unmarshal(pk)
	if x == nil {
		return fmt.Errorf("pubkey unmarshal failed")
	}

	cx.Stack[fourth].Uint = 0
	cx.Stack[fourth].Bytes, err = leadingZeros(32, x)
	if err != nil {
		return fmt.Errorf("x component zeroing failed: %s", err.Error())
	}
	cx.Stack[pprev].Uint = 0
	cx.Stack[pprev].Bytes, err = leadingZeros(32, y)
	if err != nil {
		return fmt.Errorf("y component zeroing failed: %s", err.Error())
	}
	cx.Stack = cx.Stack[:prev]
	return nil
}

type rawMessage []byte

func (rm rawMessage) ToBeHashed() (protocol.HashID, []byte) {
	return "", []byte(rm)
}

func opVrfVerify(cx *EvalContext) error {
	last := len(cx.Stack) - 1 // PK
	prev := last - 1          // proof
	pprev := prev - 1         // data

	data := rawMessage(cx.Stack[pprev].Bytes)
	proofbytes := cx.Stack[prev].Bytes
	var proof crypto.VrfProof
	if len(proofbytes) != len(proof) {
		return fmt.Errorf("vrf proof wrong size %d != %d", len(proofbytes), len(proof))
	}
	copy(proof[:], proofbytes[:])

	pubkeybytes := cx.Stack[last].Bytes
	var pubkey crypto.VrfPubkey
	if len(pubkeybytes) != len(pubkey) {
		return fmt.Errorf("vrf pubkey wrong size %d != %d", len(pubkeybytes), len(pubkey))
	}
	copy(pubkey[:], pubkeybytes[:])

	var verified bool
	var output []byte
	std := VrfStandard(cx.program[cx.pc+1])
	ss, ok := vrfStandardSpecByField(std)
	if !ok || ss.version > cx.version {
		return fmt.Errorf("invalid VRF standard %s", std)
	}
	switch std {
	case VrfAlgorand:
		var out crypto.VrfOutput
		verified, out = pubkey.Verify(proof, data)
		output = out[:]
	default:
		return fmt.Errorf("unsupported vrf_verify standard %s", std)
	}

	cx.Stack[pprev].Bytes = output[:]
	cx.Stack[prev] = boolToSV(verified)
	cx.Stack = cx.Stack[:last] // pop 1 because we take 3 args and return 2
	return nil
}
