// Copyright (C) 2019 Algorand, Inc.
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

package agreement

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var bottom proposalValue

// A proposalValue is a triplet of a block hashes (the contents themselves and the encoding of the block),
// its proposer, and the period in which it was proposed.
type proposalValue struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	OriginalPeriod   period         `codec:"oper"`
	OriginalProposer basics.Address `codec:"oprop"`
	BlockDigest      crypto.Digest  `codec:"dig"`    // = proposal.Block.Digest()
	EncodingDigest   crypto.Digest  `codec:"encdig"` // = crypto.HashObj(proposal)
}

// A transmittedPayload is the representation of a proposal payload on the wire.
type transmittedPayload struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	unauthenticatedProposal
	PriorVote unauthenticatedVote `codec:"pv"`
}

// A unauthenticatedProposal is an Block along with everything needed to validate it.
type unauthenticatedProposal struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	bookkeeping.Block
	SeedProof crypto.VrfProof `codec:"sdpf"`

	OriginalPeriod   period         `codec:"oper"`
	OriginalProposer basics.Address `codec:"oprop"`
}

// ToBeHashed implements the Hashable interface.
func (p unauthenticatedProposal) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Payload, protocol.Encode(p)
}

// value returns the proposal-value associated with this proposal.
func (p unauthenticatedProposal) value() proposalValue {
	return proposalValue{
		OriginalPeriod:   p.OriginalPeriod,
		OriginalProposer: p.OriginalProposer,
		BlockDigest:      p.Digest(),
		EncodingDigest:   crypto.HashObj(p),
	}
}

// A proposal is an Block along with everything needed to validate it.
type proposal struct {
	unauthenticatedProposal

	// ve stores an optional ValidatedBlock representing this block.
	// This allows us to avoid re-computing the state delta when
	// applying this block to the ledger.  This is not serialized
	// to disk, so after a crash, we will fall back to applying the
	// raw Block to the ledger (and re-computing the state delta).
	ve ValidatedBlock
}

func makeProposal(ve ValidatedBlock, pf crypto.VrfProof, origPer period, origProp basics.Address) proposal {
	e := ve.Block()
	var payload unauthenticatedProposal
	payload.Block = e
	payload.SeedProof = pf
	payload.OriginalPeriod = origPer
	payload.OriginalProposer = origProp
	return proposal{unauthenticatedProposal: payload, ve: ve}
}

func (p proposal) u() unauthenticatedProposal {
	return p.unauthenticatedProposal
}

// A proposerSeed is a Hashable input to proposer seed derivation.
type proposerSeed struct {
	Addr basics.Address   `codec:"addr"`
	VRF  crypto.VrfOutput `codec:"vrf"`
}

// ToBeHashed implements the Hashable interface.
func (s proposerSeed) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.ProposerSeed, protocol.Encode(s)
}

// A seedInput is a Hashable input to seed rerandomization.
type seedInput struct {
	Alpha   crypto.Digest `codec:"alpha"`
	History crypto.Digest `codec:"hist"`
}

// ToBeHashed implements the Hashable interface.
func (i seedInput) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.ProposerSeed, protocol.Encode(i)
}

func deriveNewSeed(address basics.Address, vrf *crypto.VRFSecrets, rnd round, period period, ledger LedgerReader) (newSeed committee.Seed, seedProof crypto.VRFProof, reterr error) {
	var ok bool
	var vrfOut crypto.VrfOutput

	cparams, err := ledger.ConsensusParams(ParamsRound(rnd))
	if err != nil {
		err = fmt.Errorf("failed to obtain consensus parameters in round %v: %v", ParamsRound(rnd), err)
		return
	}
	if cparams.TwinSeeds {
		var alpha crypto.Digest
		prevSeed, err := ledger.Seed(seedRound(rnd, cparams))
		if err != nil {
			reterr = fmt.Errorf("failed read seed of round %v: %v", seedRound(rnd, cparams), err)
			return
		}

		if period == 0 {
			seedProof, ok = vrf.SK.Prove(prevSeed)
			if !ok {
				reterr = fmt.Errorf("could not make seed proof")
				return
			}
			vrfOut, ok = seedProof.Hash()
			if !ok {
				// If proof2hash fails on a proof we produced with VRF Prove, this indicates our VRF code has a dangerous bug.
				// Panicking is the only safe thing to do.
				logging.Base().Panicf("VrfProof.Hash() failed on a proof we ourselves generated; this indicates a bug in the VRF code: %v", seedProof)
			}
			alpha = crypto.HashObj(proposerSeed{Addr: address, VRF: vrfOut})
		} else {
			alpha = crypto.HashObj(prevSeed)
		}

		input := seedInput{Alpha: alpha}
		rerand := rnd % basics.Round(cparams.SeedLookback*cparams.SeedRefreshInterval)
		if rerand < basics.Round(cparams.SeedLookback) {
			digrnd := rnd.SubSaturate(basics.Round(cparams.SeedLookback * cparams.SeedRefreshInterval))
			oldDigest, err := ledger.LookupDigest(digrnd)
			if err != nil {
				reterr = fmt.Errorf("could not lookup old entry digest (for seed) from round %v: %v", digrnd, err)
				return
			}
			input.History = oldDigest
		}
		newSeed = committee.Seed(crypto.HashObj(input))
		return
	}

	// Compute the new seed
	prevSeed, err := ledger.Seed(rnd.SubSaturate(1))
	if err != nil {
		reterr = fmt.Errorf("failed read seed of round %v: %v", seedRound(rnd, cparams), err)
		return
	}
	if (rnd % basics.Round(cparams.SeedLookback)) != 0 {
		// In odd rounds, the seed is just the seed from the previous round, unchanged.
		// This simplifies the analysis now that our seed lookback parameter is 2. (In the original paper it was 1.)
		newSeed = prevSeed
	} else {
		// In even rounds, we evolve the seed
		var q1 crypto.Digest
		var ok bool
		var vrfOut crypto.VrfOutput
		if period == 0 {
			// For period 0, the proposer runs the previous seed through their VRF.
			// To an adversary trying to predict (or influence) future seeds, as soon as there's an honest proposer the seed becomes completely rerandomized.
			// This is because a VRF output is pseudorandom to anyone without the secret key or the corresponding proof.
			// The adversary's ability to influence the seed is also limited because of the uniqueness property of the VRF.
			seedProof, ok = vrf.SK.Prove(prevSeed)
			if !ok {
				reterr = fmt.Errorf("Could not make seed proof")
				return
			}
			vrfOut, ok = seedProof.Hash()
			if !ok {
				// If proof2hash fails on a proof we produced with VRF Prove, this indicates our VRF code has a dangerous bug.
				// Panicking is the only safe thing to do.
				logging.Base().Panicf("VrfProof.Hash() failed on a proof we ourselves generated; this indicates a bug in the VRF code: %v", seedProof)
			}
			// Hashing in the proposer's address is not strictly speaking necessary.
			// We do it here to be consistent with Credentials, where hashing the address in with the VRF output is necessary to prevent a specific attack.
			q1 = crypto.Hash(append(vrfOut[:], address[:]...))
		} else {
			// For periods > 0, we don't use the proposer's VRF or address.
			// This limits an adversary's ability to influence the seed.
			// In particular, some of the adversary's accounts may be likely to be selected in period 0, others in period 1, and so on.
			// If the adversary doesn't like any of the seeds from any of their period-0 possible proposers, they might try causing the network to move on to the next period until they reach a period where one of their likely proposers gives them a good seed.
			// By making periods > 0 give only one possible seed, this limits the number of new seeds the adversary can choose between.
			q1 = crypto.Hash(prevSeed[:])
		}

		// Periodically mix an older block hash (which either implicitly or explicitly commits to the balances) into the seed.
		// This prevents a specific attack wherein an attacker during a long partition can cause the network to permanently stall even after the partition has healed.
		// In particular, during a partition, the adversary can (by dropping other proposals) propose every block.
		// Thus they can predict (and to some extent influence) seed values for future rounds that are during the partition.
		// Say the partition is going to end just before round R. In round R, proposers are selected using the seed from round (R-SeedLookback)
		// and the balances / VRF keys from round (R-BalLookback), both of which are during the partition.
		// Say we're before (R-BalLookback). Because the adversary knows what the seed will be at round R-(SeedLookback), they can find
		// (by brute force) and register VRF public keys that give extremely good credentials (disproportionate to stake) for being round R proposer in period 0.
		// Likewise they can register VRF public keys that will make them be proposer in round R period 1, and period 2, and so on for all periods.
		// Then even after the partition has healed, the adversary can permanently stall the network because they will be selected in every period of round R and can keep proposing bad blocks.
		// Periodically mixing the block hash into the seed defeats this attack: any change to the balances / VRF keys registered in round (R-BalLookback) will cause the seed in round (R-SeedLookback) to change. So by brute force the adversary may be able to make themselves leader in a few periods of round R but certainly not all of them, and they won't be able to stall the network after the partition has healed.
		if rnd%basics.Round(cparams.SeedRefreshInterval) == 0 {
			oldDigest, err := ledger.LookupDigest(rnd.SubSaturate(basics.Round(cparams.SeedRefreshInterval)))
			if err != nil {
				reterr = fmt.Errorf("Could not lookup old entry digest (for seed): %v", err)
				return
			}
			q1 = crypto.Hash(append(q1[:], oldDigest[:]...))
		}
		newSeed = committee.Seed(q1)
	}
	return
}

func verifyNewSeed(p unauthenticatedProposal, ledger LedgerReader) error {
	value := p.value()
	rnd := p.Round()
	cparams, err := ledger.ConsensusParams(ParamsRound(rnd))
	if err != nil {
		return fmt.Errorf("failed to obtain consensus parameters in round %v: %v", ParamsRound(rnd), err)
	}

	balanceRound := balanceRound(rnd, cparams)
	proposerRecord, err := ledger.BalanceRecord(balanceRound, value.OriginalProposer)
	if err != nil {
		return fmt.Errorf("failed to obtain balance record for address %v in round %v: %v", value.OriginalProposer, balanceRound, err)
	}

	if cparams.TwinSeeds {
		var alpha crypto.Digest
		prevSeed, err := ledger.Seed(seedRound(rnd, cparams))
		if err != nil {
			return fmt.Errorf("failed read seed of round %v: %v", seedRound(rnd, cparams), err)
		}

		if value.OriginalPeriod == 0 {
			verifier := proposerRecord.SelectionID
			ok, vrfOut := verifier.Verify(p.SeedProof, prevSeed)
			if !ok {
				return fmt.Errorf("payload seed proof malformed (%v, %v)", prevSeed, p.SeedProof)
			}
			vrfOut, ok = p.SeedProof.Hash()
			if !ok {
				// If proof2hash fails on a proof we produced with VRF Prove, this indicates our VRF code has a dangerous bug.
				// Panicking is the only safe thing to do.
				logging.Base().Panicf("VrfProof.Hash() failed on a proof we ourselves generated; this indicates a bug in the VRF code: %v", p.SeedProof)
			}
			alpha = crypto.HashObj(proposerSeed{Addr: proposerRecord.Addr, VRF: vrfOut})
		} else {
			alpha = crypto.HashObj(prevSeed)
		}

		input := seedInput{Alpha: alpha}
		rerand := rnd % basics.Round(cparams.SeedLookback*cparams.SeedRefreshInterval)
		if rerand < basics.Round(cparams.SeedLookback) {
			digrnd := rnd.SubSaturate(basics.Round(cparams.SeedLookback * cparams.SeedRefreshInterval))
			oldDigest, err := ledger.LookupDigest(digrnd)
			if err != nil {
				return fmt.Errorf("could not lookup old entry digest (for seed) from round %v: %v", digrnd, err)
			}
			input.History = oldDigest
		}
		if p.Seed() != committee.Seed(crypto.HashObj(input)) {
			return fmt.Errorf("payload seed malformed (%v != %v)", committee.Seed(crypto.HashObj(input)), p.Seed())
		}
	} else {
		prevSeed, err := ledger.Seed(p.Round().SubSaturate(1))
		if err != nil {
			return fmt.Errorf("could not perform ledger read for prevSeed: %v", err)
		}

		// Check the seed is computed correctly. See comments in proposalForBlock() for details.
		if p.Round()%basics.Round(cparams.SeedLookback) != 0 {
			if p.Seed() != prevSeed {
				return fmt.Errorf("payload seed malformed")
			}
		} else {
			var q1 crypto.Digest
			if value.OriginalPeriod == 0 {
				verifier := proposerRecord.SelectionID
				ok, vrfOut := verifier.Verify(p.SeedProof, prevSeed)
				if !ok {
					return fmt.Errorf("payload seed proof malformed (%v, %v)", prevSeed, p.SeedProof)
				}
				q1 = crypto.Hash(append(vrfOut[:], proposerRecord.Addr[:]...))
			} else {
				q1 = crypto.Hash(prevSeed[:])
			}

			if p.Round()%basics.Round(cparams.SeedRefreshInterval) == 0 {
				oldDigest, err := ledger.LookupDigest(p.Round().SubSaturate(basics.Round(cparams.SeedRefreshInterval)))
				if err != nil {
					return fmt.Errorf("could not perform ledger read for oldDigest: %v", err)
				}
				q1 = crypto.Hash(append(q1[:], oldDigest[:]...))
			}

			if p.Seed() != committee.Seed(q1) {
				return fmt.Errorf("payload seed malformed (%v != %v)", committee.Seed(q1), p.Seed())
			}
		}
	}
	return nil
}

func proposalForBlock(address basics.Address, vrf *crypto.VRFSecrets, ve ValidatedBlock, period period, ledger LedgerReader) (proposal, proposalValue, error) {
	rnd := ve.Block().Round()
	newSeed, seedProof, err := deriveNewSeed(address, vrf, rnd, period, ledger)
	if err != nil {
		return proposal{}, proposalValue{}, fmt.Errorf("proposalForBlock: could not derive new seed: %v", err)
	}

	ve = ve.WithSeed(newSeed)
	proposal := makeProposal(ve, seedProof, period, address)
	value := proposalValue{
		OriginalPeriod:   period,
		OriginalProposer: address,
		BlockDigest:      proposal.Block.Digest(),
		EncodingDigest:   crypto.HashObj(proposal),
	}
	return proposal, value, nil
}

// validate returns true if the proposal is valid.
// It checks the proposal seed and then calls validator.Validate.
func (p unauthenticatedProposal) validate(ctx context.Context, current round, ledger LedgerReader, validator BlockValidator) (proposal, error) {
	var invalid proposal
	entry := p.Block

	if entry.Round() != current {
		return invalid, fmt.Errorf("proposed entry from wrong round: entry.Round() != current: %v != %v", entry.Round(), current)
	}

	err := verifyNewSeed(p, ledger)
	if err != nil {
		return invalid, fmt.Errorf("proposal has bad seed: %v", err)
	}

	ve, err := validator.Validate(ctx, entry)
	if err != nil {
		return invalid, fmt.Errorf("EntryValidator rejected entry: %v", err)
	}

	return makeProposal(ve, p.SeedProof, p.OriginalPeriod, p.OriginalProposer), nil
}
