// Copyright (C) 2019-2024 Algorand, Inc.
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
	"time"

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

	// receivedAt indicates the time at which this proposal was
	// delivered to the agreement package (as a messageEvent),
	// relative to the zero of that round.
	receivedAt time.Duration
}

// TransmittedPayload exported for dumping textual versions of messages
type TransmittedPayload = transmittedPayload

// ToBeHashed implements the Hashable interface.
func (p unauthenticatedProposal) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Payload, protocol.Encode(&p)
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

	// validatedAt indicates the time at which this proposal was
	// validated (and thus was ready to be delivered to the state
	// machine), relative to the zero of that round.
	validatedAt time.Duration
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

	cparams, err := ledger.ConsensusParams(ParamsRound(rnd))
	if err != nil {
		reterr = fmt.Errorf("failed to obtain consensus parameters in round %d: %v", ParamsRound(rnd), err)
		return
	}
	var alpha crypto.Digest
	prevSeed, err := ledger.Seed(seedRound(rnd, cparams))
	if err != nil {
		reterr = fmt.Errorf("failed read seed of round %d: %v", seedRound(rnd, cparams), err)
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
			reterr = fmt.Errorf("could not lookup old entry digest (for seed) from round %d: %v", digrnd, err)
			return
		}
		input.History = oldDigest
	}
	newSeed = committee.Seed(crypto.HashObj(input))
	return
}

// verifyHeader checks the things in the header that can only be confirmed by
// looking into the unauthenticatedProposal or using LookupAgreement. The
// Proposer, ProposerPayout, and Seed.
func verifyHeader(p unauthenticatedProposal, ledger LedgerReader) error {
	value := p.value()
	rnd := p.Round()

	// ledger.ConsensusParams(rnd) is not allowed because rnd isn't committed.
	// The BlockHeader isn't trustworthy yet, since we haven't checked the
	// upgrade state. So, for now, we confirm that the BlockSeed is *either*
	// correct or missing. `eval` package will using Mining().Enabled to confirm
	// which it should be.
	if !p.BlockHeader.Proposer.IsZero() && p.BlockHeader.Proposer != value.OriginalProposer {
		return fmt.Errorf("wrong proposer (%v != %v)", p.Proposer, value.OriginalProposer)
	}

	// Similarly, we only check here that the payout is zero if
	// ineligibile. `eval` code must check that it is correct if > 0.
	eligible, err := payoutEligible(rnd, p.Proposer, ledger)
	if err != nil {
		return fmt.Errorf("failed to determine incentive eligibility %w", err)
	}
	if !eligible && p.BlockHeader.ProposerPayout.Raw > 0 {
		return fmt.Errorf("proposer payout (%d) for ineligible Proposer %v",
			p.BlockHeader.ProposerPayout.Raw, p.Proposer)
	}

	cparams, err := ledger.ConsensusParams(ParamsRound(rnd))
	if err != nil {
		return fmt.Errorf("failed to obtain consensus parameters in round %d: %v", ParamsRound(rnd), err)
	}

	balanceRound := balanceRound(rnd, cparams)
	proposerRecord, err := ledger.LookupAgreement(balanceRound, value.OriginalProposer)
	if err != nil {
		return fmt.Errorf("failed to obtain balance record for address %v in round %d: %v", value.OriginalProposer, balanceRound, err)
	}

	var alpha crypto.Digest
	prevSeed, err := ledger.Seed(seedRound(rnd, cparams))
	if err != nil {
		return fmt.Errorf("failed to read seed of round %d: %v", seedRound(rnd, cparams), err)
	}

	if value.OriginalPeriod == 0 {
		verifier := proposerRecord.SelectionID
		ok, _ := verifier.Verify(p.SeedProof, prevSeed) // ignoring VrfOutput returned by Verify
		if !ok {
			return fmt.Errorf("seed proof malformed (%v, %v)", prevSeed, p.SeedProof)
		}
		// TODO remove the following Hash() call,
		// redundant with the Verify() call above.
		vrfOut, ok := p.SeedProof.Hash()
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
	rerand := rnd % basics.Round(cparams.SeedLookback*cparams.SeedRefreshInterval)
	if rerand < basics.Round(cparams.SeedLookback) {
		digrnd := rnd.SubSaturate(basics.Round(cparams.SeedLookback * cparams.SeedRefreshInterval))
		oldDigest, err := ledger.LookupDigest(digrnd)
		if err != nil {
			return fmt.Errorf("could not lookup old entry digest (for seed) from round %d: %v", digrnd, err)
		}
		input.History = oldDigest
	}
	if p.Seed() != committee.Seed(crypto.HashObj(input)) {
		return fmt.Errorf("seed malformed (%v != %v)", committee.Seed(crypto.HashObj(input)), p.Seed())
	}
	return nil
}

// payoutEligible determines whether the proposer is eligible for block incentive payout.
func payoutEligible(rnd basics.Round, proposer basics.Address, ledger LedgerReader) (bool, error) {
	// We want to check eligibility of the online balance in the round that
	// mattered to select this proposer.
	agreementParams, err := ledger.ConsensusParams(ParamsRound(rnd))
	if err != nil {
		return false, err
	}

	// Check the balance from the agreement round
	balanceRound := balanceRound(rnd, agreementParams)
	balanceRecord, err := ledger.LookupAgreement(balanceRound, proposer)
	if err != nil {
		return false, err
	}

	balanceParams, err := ledger.ConsensusParams(balanceRound)
	if err != nil {
		return false, err
	}

	// It's only fair to compare balance's from 320 rounds ago to the mining
	// rules that were in effect then.  To make this work in a reasonable way
	// when mining begins, the miningRules[0] in consensus.go has Min and Max.
	eligible := balanceRecord.IncentiveEligible &&
		balanceRecord.MicroAlgosWithRewards.Raw >= balanceParams.Mining().MinBalance &&
		balanceRecord.MicroAlgosWithRewards.Raw <= balanceParams.Mining().MaxBalance
	return eligible, nil
}

func proposalForBlock(address basics.Address, vrf *crypto.VRFSecrets, ve ValidatedBlock, period period, ledger LedgerReader) (proposal, proposalValue, error) {
	blk := ve.Block()
	newSeed, seedProof, err := deriveNewSeed(address, vrf, blk.Round(), period, ledger)
	if err != nil {
		return proposal{}, proposalValue{}, fmt.Errorf("proposalForBlock: could not derive new seed: %w", err)
	}

	eligible, err := payoutEligible(blk.Round(), address, ledger)
	if err != nil {
		return proposal{}, proposalValue{}, fmt.Errorf("proposalForBlock: could determine eligibility: %w", err)
	}

	ve = ve.WithProposal(newSeed, address, eligible)
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

	err := verifyHeader(p, ledger)
	if err != nil {
		return invalid, fmt.Errorf("unable to verify header: %w", err)
	}

	ve, err := validator.Validate(ctx, entry)
	if err != nil {
		return invalid, fmt.Errorf("EntryValidator rejected entry: %w", err)
	}

	return makeProposal(ve, p.SeedProof, p.OriginalPeriod, p.OriginalProposer), nil
}
