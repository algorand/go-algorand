package compactcert

import (
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/data/basics"
)

//msgp:ignore sigslot
type sigslot struct {
	// part is the participant signing this message.  The participant
	// information is tracked here for convenience, but it does not
	// appear in the commitment to the sigs array.
	part Participant

	// Include the parts of the sigslot that form the commitment to
	// the sigs array.
	sigslotCommit
}

// Builder keeps track of signatures on a message and eventually produces
// a compact certificate for that message.
type Builder struct {
	Params

	sigs         []sigslot // Indexed by pos in participants
	signedWeight uint64    // Total weight of signatures so far
	participants []Participant
	parttree     *merklearray.Tree
}

// MkBuilder constructs an empty builder (with no signatures).  The message
// to be signed, as well as other security parameters, are specified in
// param.  The participants that will sign the message are in part and
// parttree.
func MkBuilder(param Params, part []Participant, parttree *merklearray.Tree) (*Builder, error) {
	npart := len(part)

	b := &Builder{
		Params:       param,
		sigs:         make([]sigslot, npart),
		signedWeight: 0,
		participants: part,
		parttree:     parttree,
	}

	return b, nil
}

// Present checks if the builder already contains a signature at a particular
// offset.
func (b *Builder) Present(pos uint64) bool {
	return b.sigs[pos].part.Weight != 0
}

// Add a signature to the set of signatures available for building a certificate.
// verifySig should be set to true in production; setting it to false is useful
// for benchmarking to avoid the cost of signature checks.
func (b *Builder) Add(pos uint64, sig crypto.OneTimeSignature, verifySig bool) error {
	if b.Present(pos) {
		return fmt.Errorf("position %d already added", pos)
	}

	// Check participants array
	if pos >= uint64(len(b.participants)) {
		return fmt.Errorf("pos %d >= len(participants) %d", pos, len(b.participants))
	}

	p := b.participants[pos]

	if p.Weight == 0 {
		return fmt.Errorf("position %d has zero weight", pos)
	}

	// Check signature
	ephID := basics.OneTimeIDForRound(b.SigRound, p.KeyDilution)
	if verifySig && !p.PK.Verify(ephID, b.Msg, sig) {
		return fmt.Errorf("signature does not verify under ID %v", ephID)
	}

	// Remember the signature
	b.sigs[pos].part = p
	b.sigs[pos].Sig.OneTimeSignature = sig
	b.signedWeight += p.Weight
	return nil
}

// Ready returns whether the certificate is ready to be built.
func (b *Builder) Ready() bool {
	return b.signedWeight >= b.Params.ProvenWeight
}

// SignedWeight returns the total weight of signatures added so far.
func (b *Builder) SignedWeight() uint64 {
	return b.signedWeight
}

//msgp:ignore sigCommit
type sigCommit []sigslot

func (sc sigCommit) Length() uint64 {
	return uint64(len(sc))
}

func (sc sigCommit) Get(pos uint64) (crypto.Hashable, error) {
	if pos >= uint64(len(sc)) {
		return nil, fmt.Errorf("pos %d past end %d", pos, len(sc))
	}

	return &sc[pos].sigslotCommit, nil
}

// coinIndex returns the position pos in the sigs array such that the sum
// of all signature weights before pos is less than or equal to coinWeight,
// but the sum of all signature weights up to and including pos exceeds
// coinWeight.
//
// coinIndex works by doing a binary search on the sigs array.  The caller
// should invoke it with lo=0 and hi=len(b.sigs).  The caller should make
// sure that sigs[*].l is initialized before using coinIndex().
func (b *Builder) coinIndex(coinWeight uint64, lo uint64, hi uint64) (uint64, error) {
	if lo >= hi {
		return 0, fmt.Errorf("coinIndex: lo %d >= hi %d", lo, hi)
	}

	mid := (lo + hi) / 2
	if coinWeight < b.sigs[mid].L {
		return b.coinIndex(coinWeight, lo, mid)
	}

	if coinWeight < b.sigs[mid].L+b.sigs[mid].part.Weight {
		return mid, nil
	}

	return b.coinIndex(coinWeight, mid+1, hi)
}

// Build returns a compact certificate, if the builder has accumulated
// enough signatures to construct it.
func (b *Builder) Build() (*Cert, error) {
	if b.signedWeight < b.Params.ProvenWeight {
		return nil, fmt.Errorf("not enough signed weight: %d < %d", b.signedWeight, b.Params.ProvenWeight)
	}

	// Commit to the sigs array
	for i := 1; i < len(b.sigs); i++ {
		b.sigs[i].L = b.sigs[i-1].L + b.sigs[i-1].part.Weight
	}

	sigtree, err := merklearray.Build(sigCommit(b.sigs))
	if err != nil {
		return nil, err
	}

	// Reveal sufficient number of signatures
	c := &Cert{
		SigCommit:    sigtree.Root(),
		SignedWeight: b.signedWeight,
		Reveals:      nil,
	}

	nr, err := b.numReveals(b.signedWeight)
	if err != nil {
		return nil, err
	}

	var proofPositions []uint64

	for j := uint64(0); j < nr; j++ {
		coin := hashCoin(j, c.SigCommit, c.SignedWeight)
		pos, err := b.coinIndex(coin, 0, uint64(len(b.sigs)))
		if err != nil {
			return nil, err
		}

		if pos >= uint64(len(b.participants)) {
			return nil, fmt.Errorf("pos %d >= len(participants) %d", pos, len(b.participants))
		}

		// If we already revealed pos, no need to do it again
		alreadyRevealed := false
		for _, r := range c.Reveals {
			if r.Pos == pos {
				alreadyRevealed = true
			}
		}

		if alreadyRevealed {
			continue
		}

		// Generate the reveal for pos
		r := Reveal{
			Pos:     pos,
			SigSlot: b.sigs[pos].sigslotCommit,
			Part:    b.participants[pos],
		}

		c.Reveals = append(c.Reveals, r)
		proofPositions = append(proofPositions, pos)
	}

	c.SigProofs, err = sigtree.Prove(proofPositions)
	if err != nil {
		return nil, err
	}

	c.PartProofs, err = b.parttree.Prove(proofPositions)
	if err != nil {
		return nil, err
	}

	return c, nil
}
