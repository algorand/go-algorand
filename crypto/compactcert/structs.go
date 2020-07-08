package compactcert

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// Params defines common parameters for the verifier and builder.
type Params struct {
	Msg          crypto.Hashable // Message to be cerified
	ProvenWeight uint64          // Weight threshold proven by the certificate
	SigRound     basics.Round    // Ephemeral signature round to expect
	SecKQ        uint64          // Security parameter (k+q) from analysis document
}

// A Participant corresponds to an account whose AccountData.Status
// is Online, and for which the expected sigRound satisfies
// AccountData.VoteFirstValid <= sigRound <= AccountData.VoteLastValid.
//
// In the Algorand ledger, it is possible for multiple accounts to have
// the same PK.  Thus, the PK is not necessarily unique among Participants.
// However, each account will produce a unique Participant struct, to avoid
// potential DoS attacks where one account claims to have the same VoteID PK
// as another account.
type Participant struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// PK is AccountData.VoteID.
	PK crypto.OneTimeSignatureVerifier `codec:"p"`

	// Weight is AccountData.MicroAlgos.
	Weight uint64 `codec:"w"`

	// KeyDilution is AccountData.KeyDilution() with the protocol for sigRound
	// as expected by the Builder.
	KeyDilution uint64 `codec:"d"`
}

func (p Participant) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.CompactCertPart, protocol.Encode(&p)
}

// CompactOneTimeSignature is crypto.OneTimeSignature with omitempty
type CompactOneTimeSignature struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	crypto.OneTimeSignature
}

// A sigslotCommit is a single slot in the sigs array that forms the certificate.
type sigslotCommit struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Sig is a signature by the participant on the expected message.
	Sig CompactOneTimeSignature `codec:"s"`

	// L is the total weight of signatures in lower-numbered slots.
	// This is initialized once the builder has collected a sufficient
	// number of signatures.
	L uint64 `codec:"l"`
}

func (ssc sigslotCommit) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.CompactCertSig, protocol.Encode(&ssc)
}

type Reveal struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Pos     uint64        `codec:"i"`
	SigSlot sigslotCommit `codec:"s"`
	Part    Participant   `codec:"p"`
}

// maxReveals is a bound on allocation and on numReveals to limit log computation
const maxReveals = 1024
const maxProofDigests = 20 * maxReveals

type Cert struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SigCommit    crypto.Digest   `codec:"c"`
	SignedWeight uint64          `codec:"w"`
	SigProofs    []crypto.Digest `codec:"S,allocbound=maxProofDigests"`
	PartProofs   []crypto.Digest `codec:"P,allocbound=maxProofDigests"`
	Reveals      []Reveal        `codec:"r,allocbound=maxReveals"`
}
