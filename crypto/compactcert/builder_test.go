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
	"context"
	"database/sql"
	"fmt"
	"github.com/algorand/go-algorand/config"
	"strconv"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklekeystore"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
	"github.com/stretchr/testify/require"
)

type TestMessage string

// TODO: change to CurrentVersion when updated
var CompactCertRounds = config.Consensus[protocol.ConsensusFuture].CompactCertRounds

func (m TestMessage) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Message, []byte(m)
}

type PartCommit struct {
	participants []basics.Participant
}

func (pc PartCommit) Length() uint64 {
	return uint64(len(pc.participants))
}

func (pc PartCommit) Marshal(pos uint64) ([]byte, error) {
	if pos >= uint64(len(pc.participants)) {
		return nil, fmt.Errorf("pos %d >= len %d", pos, len(pc.participants))
	}

	return crypto.HashRep(pc.participants[pos]), nil
}

func createParticipantSliceWithWeight(totalWeight, numberOfParticipant int, key *merklekeystore.Signer) []basics.Participant {
	parts := make([]basics.Participant, 0, numberOfParticipant)

	for i := 0; i < numberOfParticipant; i++ {
		part := basics.Participant{
			PK:         *key.GetVerifier(),
			Weight:     uint64(totalWeight / 2 / numberOfParticipant),
			FirstValid: 0,
		}

		parts = append(parts, part)
	}
	return parts
}

func generateTestSigner(name string, firstValid uint64, lastValid uint64, a *require.Assertions) (*merklekeystore.Signer, db.Accessor) {
	store, err := db.MakeAccessor(name, false, true)
	a.NoError(err)
	a.NotNil(store)

	err = store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err = tx.Exec(`CREATE TABLE schema (
         tablename TEXT PRIMARY KEY,
         version INTEGER
      );`)
		return err
	})
	a.NoError(err)

	signer, err := merklekeystore.New(firstValid, lastValid, CompactCertRounds, crypto.FalconType, store)
	a.NoError(err)

	err = signer.Persist()
	a.NoError(err)

	return signer, store
}

func TestBuildVerify(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	currentRound := basics.Round(128)
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
		Msg:               TestMessage("hello world"),
		ProvenWeight:      uint64(totalWeight / 2),
		SigRound:          currentRound,
		SecKQ:             128,
		CompactCertRounds: CompactCertRounds,
	}

	// Share the key; we allow the same vote key to appear in multiple accounts..
	key, dbAccessor := generateTestSigner(t.Name()+".db", 0, uint64(param.CompactCertRounds)+1, a)
	defer dbAccessor.Close()
	require.NotNil(t, dbAccessor, "failed to create signer")
	var parts []basics.Participant
	var sigs []merklekeystore.Signature
	parts = append(parts, createParticipantSliceWithWeight(totalWeight, npartHi, key)...)
	parts = append(parts, createParticipantSliceWithWeight(totalWeight, npartLo, key)...)

	sig, err := key.Sign(param.Msg, uint64(currentRound))
	require.NoError(t, err, "failed to create keys")

	for i := 0; i < npart; i++ {
		sigs = append(sigs, sig)
	}

	partcom, err := merklearray.Build(PartCommit{parts}, crypto.HashFactory{HashType: HashType})
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
	fmt.Printf("  %6d elems sigproofs\n", len(cert.SigProofs.Path))
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
	require.NoError(t, err, "failed to verify the compact cert")
}

func BenchmarkBuildVerify(b *testing.B) {
	totalWeight := 1000000
	npart := 10000
	currentRound := basics.Round(128)
	a := require.New(b)

	param := Params{
		Msg:               TestMessage("hello world"),
		ProvenWeight:      uint64(totalWeight / 2),
		SigRound:          128,
		SecKQ:             128,
		CompactCertRounds: CompactCertRounds,
	}

	var parts []basics.Participant
	var partkeys []*merklekeystore.Signer
	var sigs []merklekeystore.Signature
	for i := 0; i < npart; i++ {
		key, dbAccessor := generateTestSigner(b.Name()+"_"+strconv.Itoa(i)+"_crash.db", 0, uint64(param.CompactCertRounds)+1, a)
		defer dbAccessor.Close()
		require.NotNil(b, dbAccessor, "failed to create signer")
		part := basics.Participant{
			PK:         *key.GetVerifier(),
			Weight:     uint64(totalWeight / npart),
			FirstValid: 0,
		}

		sig, err := key.Sign(param.Msg, uint64(currentRound))
		require.NoError(b, err, "failed to create keys")

		partkeys = append(partkeys, key)
		sigs = append(sigs, sig)
		parts = append(parts, part)
	}

	var cert *Cert
	partcom, err := merklearray.Build(PartCommit{parts}, crypto.HashFactory{HashType: HashType})
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
			if err = verif.Verify(cert); err != nil {
				b.Error(err)
			}
		}
	})
}

func TestCoinIndex(t *testing.T) {
	partitiontest.PartitionTest(t)

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
