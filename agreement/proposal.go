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
	return protocol.Payload, protocol.Encode(&p)
}

func (p unauthenticatedProposal) branchRound() round {
	return round{number: p.Round(), branch: crypto.Digest(p.Branch)}
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
	_struct struct{} `codec:""` // not omitempty

	Addr basics.Address   `codec:"addr"`
	VRF  crypto.VrfOutput `codec:"vrf"`
}

// ToBeHashed implements the Hashable interface.
func (s proposerSeed) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.ProposerSeed, protocol.Encode(&s)
}

// A seedInput is a Hashable input to seed rerandomization.
type seedInput struct {
	_struct struct{} `codec:""` // not omitempty

	Alpha   crypto.Digest `codec:"alpha"`
	History crypto.Digest `codec:"hist"`
}

// ToBeHashed implements the Hashable interface.
func (i seedInput) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.ProposerSeed, protocol.Encode(&i)
}

func deriveNewSeed(address basics.Address, vrf *crypto.VRFSecrets, rnd round, period period, ledger LedgerReader) (newSeed committee.Seed, seedProof crypto.VRFProof, reterr error) {
	var ok bool
	var vrfOut crypto.VrfOutput

	cparams, err := ledger.ConsensusParams(paramsRoundBranch(rnd))
	if err != nil {
		reterr = fmt.Errorf("failed to obtain consensus parameters in round %d from round %+v: %v", ParamsRound(rnd.number), rnd, err)
		return
	}
	var alpha crypto.Digest
	prevSeed, err := ledger.Seed(seedRound(rnd.number, cparams), rnd.branch)
	if err != nil {
		reterr = fmt.Errorf("failed read seed of round %d from round %+v: %v", seedRound(rnd.number, cparams), rnd, err)
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
	rerand := rnd.number % basics.Round(cparams.SeedLookback*cparams.SeedRefreshInterval)
	if rerand < basics.Round(cparams.SeedLookback) {
		digrnd := rnd.number.SubSaturate(basics.Round(cparams.SeedLookback * cparams.SeedRefreshInterval))
		// XXXX need to remember branch from 160 rounds ago or assert that it is long enough ago to be confirmed
		oldDigest, err := ledger.LookupDigest(digrnd, crypto.Digest{})
		if err != nil {
			reterr = fmt.Errorf("could not lookup old entry digest (for seed) from round %d: %v", digrnd, err)
			return
		}
		input.History = oldDigest
	}
	newSeed = committee.Seed(crypto.HashObj(input))
	return
}

func verifyNewSeed(p unauthenticatedProposal, ledger LedgerReader) error {
	value := p.value()
	rnd := p.branchRound()
	cparams, err := ledger.ConsensusParams(paramsRoundBranch(rnd))
	if err != nil {
		return fmt.Errorf("failed to obtain consensus parameters in round %d from round %+v: %v", ParamsRound(rnd.number), rnd, err)
	}

	balanceRound := balanceRound(rnd.number, cparams)
	proposerRecord, err := ledger.Lookup(balanceRound, crypto.Digest{}, value.OriginalProposer)
	if err != nil {
		return fmt.Errorf("failed to obtain balance record for address %v in round %d: %v", value.OriginalProposer, balanceRound, err)
	}

	var alpha crypto.Digest
	prevSeed, err := ledger.Seed(seedRound(rnd.number, cparams), rnd.branch)
	if err != nil {
		return fmt.Errorf("failed read seed of round %d from rnd %+v: %v", seedRound(rnd.number, cparams), rnd, err)
	}

	if value.OriginalPeriod == 0 {
		verifier := proposerRecord.SelectionID
		ok, vrfOut := verifier.Verify(p.SeedProof, prevSeed)
		if !ok {
			return fmt.Errorf("payload seed proof malformed (%v, %v)", prevSeed, p.SeedProof)
		}
		// TODO remove the following Hash() call,
		// redundant with the Verify() call above.
		vrfOut, ok = p.SeedProof.Hash()
		if !ok {
			// If proof2hash fails on a proof we produced with VRF Prove, this indicates our VRF code has a dangerous bug.
			// Panicking is the only safe thing to do.
			logging.Base().Panicf("VrfProof.Hash() failed on a proof we ourselves generated; this indicates a bug in the VRF code: %v", p.SeedProof)
		}
		alpha = crypto.HashObj(proposerSeed{Addr: value.OriginalProposer, VRF: vrfOut})
	} else {
		alpha = crypto.HashObj(prevSeed)
	}

	input := seedInput{Alpha: alpha}
	rerand := rnd.number % basics.Round(cparams.SeedLookback*cparams.SeedRefreshInterval)
	if rerand < basics.Round(cparams.SeedLookback) {
		digrnd := rnd.number.SubSaturate(basics.Round(cparams.SeedLookback * cparams.SeedRefreshInterval))
		oldDigest, err := ledger.LookupDigest(digrnd, crypto.Digest{})
		if err != nil {
			return fmt.Errorf("could not lookup old entry digest (for seed) from round %d: %v", digrnd, err)
		}
		input.History = oldDigest
	}
	if p.Seed() != committee.Seed(crypto.HashObj(input)) {
		return fmt.Errorf("payload seed malformed (%v != %v)", committee.Seed(crypto.HashObj(input)), p.Seed())
	}
	return nil
}

func proposalForBlock(address basics.Address, vrf *crypto.VRFSecrets, ve ValidatedBlock, period period, ledger LedgerReader) (proposal, proposalValue, error) {
	rnd := round{
		number: ve.Block().Round(),
		branch: crypto.Digest(ve.Block().Branch),
	}
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

	if entry.Round() != current.number {
		return invalid, fmt.Errorf("proposed entry from wrong round: entry.Round() != current: %v != %v", entry.Round(), current)
	}
	if entry.Branch != bookkeeping.BlockHash(current.branch) { // XXX correct?
		return invalid, fmt.Errorf("proposed entry from wrong branch: entry.Round() != current: %v != %v", entry.Round(), current)
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
