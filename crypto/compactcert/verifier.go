package compactcert

import (
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/data/basics"
)

// Verifier is used to verify a compact certificate.
type Verifier struct {
	Params

	partcom crypto.Digest
}

// MkVerifier constructs a verifier to check the compact certificate
// on the message specified in p, with partcom specifying the Merkle
// root of the participants that must sign the message.
func MkVerifier(p Params, partcom crypto.Digest) *Verifier {
	return &Verifier{
		Params:  p,
		partcom: partcom,
	}
}

// Verify checks if c is a valid compact certificate for the message
// and participants that were used to construct the Verifier.
func (v *Verifier) Verify(c *Cert) error {
	if c.SignedWeight < v.ProvenWeight {
		return fmt.Errorf("cert signed weight %d < proven weight %d", c.SignedWeight, v.ProvenWeight)
	}

	// Verify all of the reveals
	sigs := make(map[uint64]crypto.Hashable)
	parts := make(map[uint64]crypto.Hashable)
	for i, r := range c.Reveals {
		sigs[r.Pos] = r.SigSlot
		parts[r.Pos] = r.Part

		ephID := basics.OneTimeIDForRound(v.SigRound, r.Part.KeyDilution)
		if !r.Part.PK.Verify(ephID, v.Msg, r.SigSlot.Sig.OneTimeSignature) {
			return fmt.Errorf("signature in reveal %d does not verify", i)
		}
	}

	err := merklearray.Verify(c.SigCommit, sigs, c.SigProofs)
	if err != nil {
		return err
	}

	err = merklearray.Verify(v.partcom, parts, c.PartProofs)
	if err != nil {
		return err
	}

	// Verify that the reveals contain the right coins
	nr, err := v.numReveals(c.SignedWeight)
	if err != nil {
		return err
	}

	for j := uint64(0); j < nr; j++ {
		coin := hashCoin(j, c.SigCommit, c.SignedWeight)
		matchingReveal := false
		for _, r := range c.Reveals {
			if r.SigSlot.L <= coin && coin < r.SigSlot.L+r.Part.Weight {
				matchingReveal = true
				break
			}
		}

		if !matchingReveal {
			return fmt.Errorf("no reveal for coin %d at %d", j, coin)
		}
	}

	return nil
}
