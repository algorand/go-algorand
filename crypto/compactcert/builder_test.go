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

package compactcert

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"

	"github.com/stretchr/testify/require"
)

type TestMessage string

func (m TestMessage) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Message, []byte(m)
}

type PartCommit struct {
	participants []Participant
}

func (pc PartCommit) Length() uint64 {
	return uint64(len(pc.participants))
}

func (pc PartCommit) GetHash(pos uint64) (crypto.Digest, error) {
	if pos >= uint64(len(pc.participants)) {
		return crypto.Digest{}, fmt.Errorf("pos %d >= len %d", pos, len(pc.participants))
	}

	return crypto.HashObj(pc.participants[pos]), nil
}

func TestBuildVerify(t *testing.T) {
	// Doing a full test of 1M accounts takes too much CPU time in CI.
	doLargeTest := false

	totalWeight := 10000000
	npartHi := 10
	npartLo := 9990

	if doLargeTest {
		npartHi *= 100
		npartLo *= 100
	}

	npart := npartHi + npartLo

	param := Params{
		Msg:          TestMessage("hello world"),
		ProvenWeight: uint64(totalWeight / 2),
		SigRound:     0,
		SecKQ:        128,
	}

	// Share the key; we allow the same vote key to appear in multiple accounts..
	key := crypto.GenerateOneTimeSignatureSecrets(0, 1)

	var parts []Participant
	var sigs []crypto.OneTimeSignature
	for i := 0; i < npartHi; i++ {
		part := Participant{
			PK:          key.OneTimeSignatureVerifier,
			Weight:      uint64(totalWeight / 2 / npartHi),
			KeyDilution: 10000,
		}

		parts = append(parts, part)
	}

	for i := 0; i < npartLo; i++ {
		part := Participant{
			PK:          key.OneTimeSignatureVerifier,
			Weight:      uint64(totalWeight / 2 / npartLo),
			KeyDilution: 10000,
		}

		parts = append(parts, part)
	}

	ephID := basics.OneTimeIDForRound(0, parts[0].KeyDilution)
	sig := key.Sign(ephID, param.Msg)

	for i := 0; i < npart; i++ {
		sigs = append(sigs, sig)
	}

	partcom, err := merklearray.Build(PartCommit{parts})
	if err != nil {
		t.Error(err)
	}

	b, err := MkBuilder(param, parts, partcom)
	if err != nil {
		t.Error(err)
	}

	for i := 0; i < npart; i++ {
		err = b.Add(uint64(i), sigs[i], !doLargeTest)
		if err != nil {
			t.Error(err)
		}
	}

	cert, err := b.Build()
	if err != nil {
		t.Error(err)
	}

	var someReveal Reveal
	for _, rev := range cert.Reveals {
		someReveal = rev
		break
	}

	certenc := protocol.Encode(cert)
	fmt.Printf("Cert size:\n")
	fmt.Printf("  %6d elems sigproofs\n", len(cert.SigProofs))
	fmt.Printf("  %6d bytes sigproofs\n", len(protocol.EncodeReflect(cert.SigProofs)))
	fmt.Printf("  %6d bytes partproofs\n", len(protocol.EncodeReflect(cert.PartProofs)))
	fmt.Printf("  %6d bytes sigproof per reveal\n", len(protocol.EncodeReflect(cert.SigProofs))/len(cert.Reveals))
	fmt.Printf("  %6d reveals:\n", len(cert.Reveals))
	fmt.Printf("    %6d bytes reveals[*] participant\n", len(protocol.Encode(&someReveal.Part)))
	fmt.Printf("    %6d bytes reveals[*] sigslot\n", len(protocol.Encode(&someReveal.SigSlot)))
	fmt.Printf("    %6d bytes reveals[*] total\n", len(protocol.Encode(&someReveal)))
	fmt.Printf("  %6d bytes total\n", len(certenc))

	verif := MkVerifier(param, partcom.Root())
	err = verif.Verify(cert)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkBuildVerify(b *testing.B) {
	totalWeight := 1000000
	npart := 10000

	param := Params{
		Msg:          TestMessage("hello world"),
		ProvenWeight: uint64(totalWeight / 2),
		SigRound:     0,
		SecKQ:        128,
	}

	var parts []Participant
	var partkeys []*crypto.OneTimeSignatureSecrets
	var sigs []crypto.OneTimeSignature
	for i := 0; i < npart; i++ {
		key := crypto.GenerateOneTimeSignatureSecrets(0, 1)
		part := Participant{
			PK:          key.OneTimeSignatureVerifier,
			Weight:      uint64(totalWeight / npart),
			KeyDilution: 10000,
		}

		ephID := basics.OneTimeIDForRound(0, part.KeyDilution)
		sig := key.Sign(ephID, param.Msg)

		partkeys = append(partkeys, key)
		sigs = append(sigs, sig)
		parts = append(parts, part)
	}

	var cert *Cert
	partcom, err := merklearray.Build(PartCommit{parts})
	if err != nil {
		b.Error(err)
	}

	b.Run("AddBuild", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			builder, err := MkBuilder(param, parts, partcom)
			if err != nil {
				b.Error(err)
			}

			for i := 0; i < npart; i++ {
				err = builder.Add(uint64(i), sigs[i], true)
				if err != nil {
					b.Error(err)
				}
			}

			cert, err = builder.Build()
			if err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			verif := MkVerifier(param, partcom.Root())
			err = verif.Verify(cert)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func TestCoinIndex(t *testing.T) {
	n := 1000
	b := &Builder{
		sigs:          make([]sigslot, n),
		sigsHasValidL: true,
	}

	for i := 0; i < n; i++ {
		b.sigs[i].L = uint64(i)
		b.sigs[i].Weight = 1
	}

	for i := 0; i < n; i++ {
		pos, err := b.coinIndex(uint64(i))
		require.NoError(t, err)
		require.Equal(t, pos, uint64(i))
	}
}
