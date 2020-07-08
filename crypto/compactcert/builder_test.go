package compactcert

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

type TestMessage string

func (m TestMessage) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Message, []byte(m)
}

type TestParticipants struct {
	p []Participant
}

func (tp TestParticipants) Lookup(pos uint64) (Participant, error) {
	if pos >= uint64(len(tp.p)) {
		return Participant{}, fmt.Errorf("pos %d too high", pos)
	}

	return tp.p[pos], nil
}

func (tp TestParticipants) Length() uint64 {
	return uint64(len(tp.p))
}

type PartCommit struct {
	participants Participants
}

func (pc PartCommit) Length() uint64 {
	return pc.participants.Length()
}

func (pc PartCommit) Get(pos uint64) (crypto.Hashable, error) {
	return pc.participants.Lookup(pos)
}

func TestBuildVerify(t *testing.T) {
	totalWeight := 10000000
	npartHi := 1000
	npartLo := 999000
	npart := npartHi + npartLo

	param := Params{
		Msg:          TestMessage("hello world"),
		ProvenWeight: uint64(totalWeight / 2),
		SigRound:     0,
		SecKQ:        128,
	}

	// Share the key; we allow the same vote key to appear in multiple accounts..
	key := crypto.GenerateOneTimeSignatureSecrets(0, 1)

	parts := TestParticipants{}
	var sigs []crypto.OneTimeSignature
	for i := 0; i < npartHi; i++ {
		part := Participant{
			PK:          key.OneTimeSignatureVerifier,
			Weight:      uint64(totalWeight / 2 / npartHi),
			KeyDilution: 10000,
		}

		parts.p = append(parts.p, part)
	}

	for i := 0; i < npartLo; i++ {
		part := Participant{
			PK:          key.OneTimeSignatureVerifier,
			Weight:      uint64(totalWeight / 2 / npartLo),
			KeyDilution: 10000,
		}

		parts.p = append(parts.p, part)
	}

	ephID := basics.OneTimeIDForRound(0, parts.p[0].KeyDilution)
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
		err = b.Add(uint64(i), sigs[i], false)
		if err != nil {
			t.Error(err)
		}
	}

	cert, err := b.Build()
	if err != nil {
		t.Error(err)
	}

	certenc := protocol.Encode(cert)
	fmt.Printf("Cert size:\n")
	fmt.Printf("  %6d elems sigproofs\n", len(cert.SigProofs))
	fmt.Printf("  %6d bytes sigproofs\n", len(protocol.EncodeReflect(cert.SigProofs)))
	fmt.Printf("  %6d bytes partproofs\n", len(protocol.EncodeReflect(cert.PartProofs)))
	fmt.Printf("  %6d bytes sigproof per reveal\n", len(protocol.EncodeReflect(cert.SigProofs))/len(cert.Reveals))
	fmt.Printf("  %6d reveals:\n", len(cert.Reveals))
	fmt.Printf("    %6d bytes reveals[0] participant\n", len(protocol.Encode(&cert.Reveals[0].Part)))
	fmt.Printf("    %6d bytes reveals[0] sigslot\n", len(protocol.Encode(&cert.Reveals[0].SigSlot)))
	fmt.Printf("    %6d bytes reveals[0] total\n", len(protocol.Encode(&cert.Reveals[0])))
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

	parts := TestParticipants{}
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
		parts.p = append(parts.p, part)
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
