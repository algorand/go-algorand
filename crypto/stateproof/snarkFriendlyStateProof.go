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

package stateproof

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
)

type snarkFriendlySigslotCommit struct {
	Sig merklesignature.SnarkFriendlySignature
	L   uint64
}

type snarkFriendlyReveal struct {
	Position  uint64
	SigSlot   snarkFriendlySigslotCommit
	SigProof  merklearray.SingleLeafProof
	Part      basics.Participant
	PartProof merklearray.SingleLeafProof
}

type snarkFriendlyStateProof struct {
	SigCommit                  crypto.GenericDigest
	SignedWeight               uint64
	MerkleSignatureSaltVersion byte
	Reveals                    []snarkFriendlyReveal
}

func (s *StateProof) createSnarkFriendlyCert(data []byte) (*snarkFriendlyStateProof, error) {
	newData := make([]byte, len(data))
	copy(newData, data)

	sigs := make(map[uint64]crypto.Hashable)
	parts := make(map[uint64]crypto.Hashable)

	for pos, r := range s.Reveals {
		sig, err := buildCommittableSignature(r.SigSlot)
		if err != nil {
			return nil, err
		}

		sigs[pos] = sig
		parts[pos] = r.Part
	}

	reveals := make([]snarkFriendlyReveal, 0, len(s.PositionsToReveal))
	for i := 0; i < len(s.PositionsToReveal); i++ {
		position := s.PositionsToReveal[i]
		reveal, ok := s.Reveals[position]
		if !ok {
			return nil, fmt.Errorf("could not find position on reveals map")
		}
		sigWithHints, err := reveal.SigSlot.Sig.CreateSNARKFriendlySignature(newData)
		if err != nil {
			return nil, err
		}
		paddedMssProof := merklearray.PadProofToMaxDepth(&reveal.SigSlot.Sig.Proof)
		sigWithHints.Proof.Path = paddedMssProof

		singleSigProof, err := merklearray.DecompressProofVC(sigs, &s.SigProofs, position)
		if err != nil {
			return nil, err
		}
		paddedSigProof := merklearray.PadProofToMaxDepth(singleSigProof)
		singleSigProof.Path = paddedSigProof

		singlePartProof, err := merklearray.DecompressProofVC(parts, &s.PartProofs, position)
		if err != nil {
			return nil, err
		}
		paddedPartProof := merklearray.PadProofToMaxDepth(singlePartProof)
		singlePartProof.Path = paddedPartProof

		sigSlot := snarkFriendlySigslotCommit{L: reveal.SigSlot.L, Sig: sigWithHints}
		reveals = append(reveals, snarkFriendlyReveal{
			Position:  position,
			SigSlot:   sigSlot,
			SigProof:  *singleSigProof,
			Part:      reveal.Part,
			PartProof: *singlePartProof})
	}

	return &snarkFriendlyStateProof{
		SigCommit:                  s.SigCommit,
		SignedWeight:               s.SignedWeight,
		MerkleSignatureSaltVersion: s.MerkleSignatureSaltVersion,
		Reveals:                    reveals,
	}, nil
}

func toZokCode(c *snarkFriendlyStateProof, verifier *Verifier, data MessageHash, round int64) string {
	// todo use the consts
	var stateproof = `
from "./state-proof.zok" import StateProof, Reveal, PublicKey, SignatureSlot, Participant, state_proof_verify
from "../mss/mss" import Sig
from "../merkle/mt-vc" import Proof, MT_VC_COMMITMENT_LEN
const u32 MAX_REVEALS = 5
const u32 DATA_LEN = 32
def main() -> bool:
	StateProof<4,4,{{len .Reveals}}> state_proof =  StateProof {
		salt_version: {{.MerkleSignatureSaltVersion}},
		signed_weight: {{.SignedWeight}},
		vc_signatures: {{.SigCommit}},
		num_reveals: {{len .Reveals}},
		reveals: [{{ range $index, $element := .Reveals}}{{if $index}},{{end}}
		Reveal {
			index: {{.Position}},
			participant: Participant {
					weight: {{.Part.Weight}},
					pk_mss: PublicKey {
							lifetime_ephemeral_pks: {{.Part.PK.KeyLifetime}}, 
							vc_ephemeral_pks: {{.Part.PK.Commitment}},
					}
				},
			sigslot: SignatureSlot {
					L: {{.SigSlot.L}},
					mss_signature: Sig {
						index: {{.SigSlot.Sig.Signature.VectorCommitmentIndex}},
						ephemeral_falcon_pk: {{.SigSlot.Sig.Signature.VerifyingKey.PublicKey}},
						proof: Proof {
							digests: {{.SigSlot.Sig.Signature.Proof.Proof.Path}},
							leaf_depth: {{.SigSlot.Sig.Signature.Proof.Proof.TreeDepth}},
						},
						falcon_ct_sig: {{.SigSlot.Sig.CTSignature}},
						s1_hint: {{.SigSlot.Sig.S1Values}},
					}
				},
			proof_participant: Proof {
					digests: {{.PartProof.Path}},
					leaf_depth: {{.PartProof.TreeDepth}},
				},
			proof_sigslot: Proof {
					digests: {{.SigProof.Path}},
					leaf_depth: {{.SigProof.TreeDepth}},
				},
		}{{ end }}],
	}
`

	buf := bytes.NewBufferString("")
	stateproofTemplate, err := template.New("stateproof").Parse(stateproof)
	if err != nil {
		panic(err)
	}
	err = stateproofTemplate.Execute(buf, c)
	if err != nil {
		panic(err)
	}
	buf.WriteString(fmt.Sprintf("	field round = %d\n", round))
	buf.WriteString(fmt.Sprintf("	u8[DATA_LEN] data = %v\n", data[:]))
	var veriferTemplate = `
	field P = {{.LnProvenWeight}}
	field target = {{.StrengthTarget}}
	u8[MT_VC_COMMITMENT_LEN] vc_participants = {{.ParticipantsCommitment}}
	assert(state_proof_verify(vc_participants,P,target,round,data,state_proof)==true)
	return true
`
	stateproofTemplate, err = template.New("verifer").Parse(veriferTemplate)
	if err != nil {
		panic(err)
	}
	err = stateproofTemplate.Execute(buf, verifier)
	if err != nil {
		panic(err)
	}
	return buf.String()
}
