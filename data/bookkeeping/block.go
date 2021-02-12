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

package bookkeeping

import (
	"fmt"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type (
	// BlockHash represents the hash of a block
	BlockHash crypto.Digest

	// A BlockHeader represents the metadata and commitments to the state of a Block.
	// The Algorand Ledger may be defined minimally as a cryptographically authenticated series of BlockHeader objects.
	BlockHeader struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Round basics.Round `codec:"rnd"`

		// The hash of the previous block
		Branch BlockHash `codec:"prev"`

		// Sortition seed
		Seed committee.Seed `codec:"seed"`

		// TxnRoot authenticates the set of transactions appearing in the block.
		// More specifically, it's the root of a merkle tree whose leaves are the block's Txids.
		// Note that the TxnRoot does not authenticate the signatures on the transactions, only the transactions themselves.
		// Two blocks with the same transactions but with different signatures will have the same TxnRoot.
		TxnRoot crypto.Digest `codec:"txn"`

		// TimeStamp in seconds since epoch
		TimeStamp int64 `codec:"ts"`

		// Genesis ID to which this block belongs.
		GenesisID string `codec:"gen"`

		// Genesis hash to which this block belongs.
		GenesisHash crypto.Digest `codec:"gh"`

		// Rewards.
		//
		// When a block is applied, some amount of rewards are accrued to
		// every account with AccountData.Status=/=NotParticipating.  The
		// amount is (thisBlock.RewardsLevel-prevBlock.RewardsLevel) of
		// MicroAlgos for every whole config.Protocol.RewardUnit of MicroAlgos in
		// that account's AccountData.MicroAlgos.
		//
		// Rewards are not compounded (i.e., not added to AccountData.MicroAlgos)
		// until some other transaction is executed on that account.
		//
		// Not compounding rewards allows us to precisely know how many algos
		// of rewards will be distributed without having to examine every
		// account to determine if it should get one more algo of rewards
		// because compounding formed another whole config.Protocol.RewardUnit
		// of algos.
		RewardsState

		// Consensus protocol versioning.
		//
		// Each block is associated with a version of the consensus protocol,
		// stored under UpgradeState.CurrentProtocol.  The protocol version
		// for a block can be determined without having to first decode the
		// block and its CurrentProtocol field, and this field is present for
		// convenience and explicitness.  Block.Valid() checks that this field
		// correctly matches the expected protocol version.
		//
		// Each block is associated with at most one active upgrade proposal
		// (a new version of the protocol).  An upgrade proposal can be made
		// by a block proposer, as long as no other upgrade proposal is active.
		// The upgrade proposal lasts for many rounds (UpgradeVoteRounds), and
		// in each round, that round's block proposer votes to support (or not)
		// the proposed upgrade.
		//
		// If enough votes are collected, the proposal is approved, and will
		// definitely take effect.  The proposal lingers for some number of
		// rounds to give clients a chance to notify users about an approved
		// upgrade, if the client doesn't support it, so the user has a chance
		// to download updated client software.
		//
		// Block proposers influence this upgrade machinery through two fields
		// in UpgradeVote: UpgradePropose, which proposes an upgrade to a new
		// protocol, and UpgradeApprove, which signals approval of the current
		// proposal.
		//
		// Once a block proposer determines its UpgradeVote, then UpdateState
		// is updated deterministically based on the previous UpdateState and
		// the new block's UpgradeVote.
		UpgradeState
		UpgradeVote

		// TxnCounter counts the number of transactions committed in the
		// ledger, from the time at which support for this feature was
		// introduced.
		//
		// Specifically, TxnCounter is the number of the next transaction
		// that will be committed after this block.  It is 0 when no
		// transactions have ever been committed (since TxnCounter
		// started being supported).
		TxnCounter uint64 `codec:"tc"`

		// CompactCert tracks the state of compact certs, potentially
		// for multiple types of certs.
		//msgp:sort protocol.CompactCertType protocol.SortCompactCertType
		CompactCert map[protocol.CompactCertType]CompactCertState `codec:"cc,allocbound=protocol.NumCompactCertTypes"`
	}

	// RewardsState represents the global parameters controlling the rate
	// at which accounts accrue rewards.
	RewardsState struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// The FeeSink accepts transaction fees. It can only spend to
		// the incentive pool.
		FeeSink basics.Address `codec:"fees"`

		// The RewardsPool accepts periodic injections from the
		// FeeSink and continually redistributes them to adresses as
		// rewards.
		RewardsPool basics.Address `codec:"rwd"`

		// RewardsLevel specifies how many rewards, in MicroAlgos,
		// have been distributed to each config.Protocol.RewardUnit
		// of MicroAlgos since genesis.
		RewardsLevel uint64 `codec:"earn"`

		// The number of new MicroAlgos added to the participation stake from rewards at the next round.
		RewardsRate uint64 `codec:"rate"`

		// The number of leftover MicroAlgos after the distribution of RewardsRate/rewardUnits
		// MicroAlgos for every reward unit in the next round.
		RewardsResidue uint64 `codec:"frac"`

		// The round at which the RewardsRate will be recalculated.
		RewardsRecalculationRound basics.Round `codec:"rwcalr"`
	}

	// UpgradeVote represents the vote of the block proposer with
	// respect to protocol upgrades.
	UpgradeVote struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// UpgradePropose indicates a proposed upgrade
		UpgradePropose protocol.ConsensusVersion `codec:"upgradeprop"`

		// UpgradeDelay indicates the time between acceptance and execution
		UpgradeDelay basics.Round `codec:"upgradedelay"`

		// UpgradeApprove indicates a yes vote for the current proposal
		UpgradeApprove bool `codec:"upgradeyes"`
	}

	// UpgradeState tracks the protocol upgrade state machine.  It is,
	// strictly speaking, computable from the history of all UpgradeVotes
	// but we keep it in the block for explicitness and convenience
	// (instead of materializing it separately, like balances).
	//msgp:ignore UpgradeState
	UpgradeState struct {
		CurrentProtocol       protocol.ConsensusVersion `codec:"proto"`
		NextProtocol          protocol.ConsensusVersion `codec:"nextproto"`
		NextProtocolApprovals uint64                    `codec:"nextyes"`
		// NextProtocolVoteBefore specify the last voting round for the next protocol proposal. If there is no voting for
		// an upgrade taking place, this would be zero.
		NextProtocolVoteBefore basics.Round `codec:"nextbefore"`
		// NextProtocolSwitchOn specify the round number at which the next protocol would be adopted. If there is no upgrade taking place,
		// nor a wait for the next protocol, this would be zero.
		NextProtocolSwitchOn basics.Round `codec:"nextswitch"`
	}

	// CompactCertState tracks the state of compact certificates.
	CompactCertState struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// CompactCertVoters is the root of a Merkle tree containing the
		// online accounts that will help sign a compact certificate.  The
		// Merkle root, and the compact certificate, happen on blocks that
		// are a multiple of ConsensusParams.CompactCertRounds.  For blocks
		// that are not a multiple of ConsensusParams.CompactCertRounds,
		// this value is zero.
		CompactCertVoters crypto.Digest `codec:"v"`

		// CompactCertVotersTotal is the total number of microalgos held by
		// the accounts in CompactCertVoters (or zero, if the merkle root is
		// zero).  This is intended for computing the threshold of votes to
		// expect from CompactCertVoters.
		CompactCertVotersTotal basics.MicroAlgos `codec:"t"`

		// CompactCertNextRound is the next round for which we will accept
		// a CompactCert transaction.
		CompactCertNextRound basics.Round `codec:"n"`
	}

	// A Block contains the Payset and metadata corresponding to a given Round.
	Block struct {
		BlockHeader
		Payset transactions.Payset `codec:"txns"`
	}
)

// Hash returns the hash of a block header.
// The hash of a block is the hash of its header.
func (bh BlockHeader) Hash() BlockHash {
	return BlockHash(crypto.HashObj(bh))
}

// ToBeHashed implements the crypto.Hashable interface
func (bh BlockHeader) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.BlockHeader, protocol.Encode(&bh)
}

// Digest returns a cryptographic digest summarizing the Block.
func (block Block) Digest() crypto.Digest {
	return crypto.Digest(block.BlockHeader.Hash())
}

// Round returns the Round for which the Block is relevant
func (block Block) Round() basics.Round {
	return block.BlockHeader.Round
}

// ConsensusProtocol returns the consensus protocol params for a block
func (block Block) ConsensusProtocol() config.ConsensusParams {
	return config.Consensus[block.BlockHeader.CurrentProtocol]
}

// GenesisID returns the genesis ID from the block header
func (block Block) GenesisID() string {
	return block.BlockHeader.GenesisID
}

// GenesisHash returns the genesis hash from the block header
func (block Block) GenesisHash() crypto.Digest {
	return block.BlockHeader.GenesisHash
}

// WithSeed returns a copy of the Block with the seed set to s.
func (block Block) WithSeed(s committee.Seed) Block {
	c := block
	c.BlockHeader.Seed = s
	return c
}

// Seed returns the Block's random seed.
func (block *Block) Seed() committee.Seed {
	return block.BlockHeader.Seed
}

// NextRewardsState computes the RewardsState of the subsequent round
// given the subsequent consensus parameters, along with the incentive pool
// balance and the total reward units in the system as of the current round.
func (s RewardsState) NextRewardsState(nextRound basics.Round, nextProto config.ConsensusParams, incentivePoolBalance basics.MicroAlgos, totalRewardUnits uint64) (res RewardsState) {
	res = s

	if nextRound == s.RewardsRecalculationRound {
		maxSpentOver := nextProto.MinBalance
		overflowed := false

		if nextProto.PendingResidueRewards {
			maxSpentOver, overflowed = basics.OAdd(maxSpentOver, s.RewardsResidue)
			if overflowed {
				logging.Base().Errorf("overflowed when trying to accumulate MinBalance(%d) and RewardsResidue(%d) for round %d (state %+v)", nextProto.MinBalance, s.RewardsResidue, nextRound, s)
				// this should never happen, but if it does, adjust the maxSpentOver so that we will have no rewards.
				maxSpentOver = incentivePoolBalance.Raw
			}
		}

		// it is time to refresh the rewards rate
		newRate, overflowed := basics.OSub(incentivePoolBalance.Raw, maxSpentOver)
		if overflowed {
			logging.Base().Errorf("overflowed when trying to refresh RewardsRate for round %v (state %+v)", nextRound, s)
			newRate = 0
		}

		res.RewardsRate = newRate / nextProto.RewardsRateRefreshInterval
		res.RewardsRecalculationRound = nextRound + basics.Round(nextProto.RewardsRateRefreshInterval)
	}

	if totalRewardUnits == 0 {
		// there are no reward units, so keep the previous rewards level
		return
	}

	var ot basics.OverflowTracker
	rewardsWithResidue := ot.Add(s.RewardsRate, s.RewardsResidue)
	var nextRewardLevel uint64
	var nextResidue uint64
	if nextProto.RewardPoolMinBalance {
		if rewardsWithResidue >= nextProto.MinBalance {
			// remove the min balance out, so that we won't be spending it.
			rewardsWithResidue = rewardsWithResidue - nextProto.MinBalance
			// calculate the new effective rewards level
			nextRewardLevel = ot.Add(s.RewardsLevel, rewardsWithResidue/totalRewardUnits)
			// calculate the next residue by figuring how many algos were not included in the previous level(s), and add back the min balance that we kept aside.
			nextResidue = nextProto.MinBalance + (rewardsWithResidue % totalRewardUnits)
		} else {
			// we don't have enough money, so keep previous level
			nextRewardLevel = s.RewardsLevel
			// and accumulate the rewards.
			nextResidue = rewardsWithResidue
		}
	} else {
		nextRewardLevel = ot.Add(s.RewardsLevel, rewardsWithResidue/totalRewardUnits)
		nextResidue = rewardsWithResidue % totalRewardUnits
	}

	if ot.Overflowed {
		logging.Base().Errorf("could not compute next reward level (current level %v, adding %v MicroAlgos in total, number of reward units %v) using old level",
			s.RewardsLevel, s.RewardsRate, totalRewardUnits)
		return
	}

	res.RewardsLevel = nextRewardLevel
	res.RewardsResidue = nextResidue

	return
}

// applyUpgradeVote determines the UpgradeState for a block at round r,
// given the previous block's UpgradeState "s" and this block's UpgradeVote.
//
// This function returns an error if the input is not valid in prevState: that
// is, if UpgradePropose shows up when there is already an active proposal, or
// if UpgradeApprove shows up if there is no active proposal being voted on.
func (s UpgradeState) applyUpgradeVote(r basics.Round, vote UpgradeVote) (res UpgradeState, err error) {
	// Locate the config parameters for current protocol
	params, ok := config.Consensus[s.CurrentProtocol]
	if !ok {
		err = fmt.Errorf("applyUpgradeVote: unsupported protocol %v", s.CurrentProtocol)
		return
	}

	// Apply proposal of upgrade to new protocol
	if vote.UpgradePropose != "" {
		if s.NextProtocol != "" {
			err = fmt.Errorf("applyUpgradeVote: new proposal during existing proposal")
			return
		}

		if len(vote.UpgradePropose) > params.MaxVersionStringLen {
			err = fmt.Errorf("applyUpgradeVote: proposed protocol version %s too long", vote.UpgradePropose)
			return
		}

		upgradeDelay := uint64(vote.UpgradeDelay)
		if upgradeDelay > params.MaxUpgradeWaitRounds || upgradeDelay < params.MinUpgradeWaitRounds {
			err = fmt.Errorf("applyUpgradeVote: proposed upgrade wait rounds %d out of permissible range [%d, %d]", upgradeDelay, params.MinUpgradeWaitRounds, params.MaxUpgradeWaitRounds)
			return
		}

		if upgradeDelay == 0 {
			upgradeDelay = params.DefaultUpgradeWaitRounds
		}

		s.NextProtocol = vote.UpgradePropose
		s.NextProtocolApprovals = 0
		s.NextProtocolVoteBefore = r + basics.Round(params.UpgradeVoteRounds)
		s.NextProtocolSwitchOn = r + basics.Round(params.UpgradeVoteRounds) + basics.Round(upgradeDelay)
	} else {
		if vote.UpgradeDelay != 0 {
			err = fmt.Errorf("applyUpgradeVote: upgrade delay %d nonzero when not proposing", vote.UpgradeDelay)
			return
		}
	}

	// Apply approval of existing protocol upgrade
	if vote.UpgradeApprove {
		if s.NextProtocol == "" {
			err = fmt.Errorf("applyUpgradeVote: approval without an active proposal")
			return
		}

		if r >= s.NextProtocolVoteBefore {
			err = fmt.Errorf("applyUpgradeVote: approval after vote deadline")
			return
		}

		s.NextProtocolApprovals++
	}

	// Clear out failed proposal
	if r == s.NextProtocolVoteBefore && s.NextProtocolApprovals < params.UpgradeThreshold {
		s.NextProtocol = ""
		s.NextProtocolApprovals = 0
		s.NextProtocolVoteBefore = basics.Round(0)
		s.NextProtocolSwitchOn = basics.Round(0)
	}

	// Switch over to new approved protocol
	if r == s.NextProtocolSwitchOn {
		s.CurrentProtocol = s.NextProtocol
		s.NextProtocol = ""
		s.NextProtocolApprovals = 0
		s.NextProtocolVoteBefore = basics.Round(0)
		s.NextProtocolSwitchOn = basics.Round(0)
	}

	res = s
	return
}

// ProcessUpgradeParams determines our upgrade vote, applies it, and returns
// the generated UpgradeVote and the new UpgradeState
func ProcessUpgradeParams(prev BlockHeader) (uv UpgradeVote, us UpgradeState, err error) {
	// Find parameters for current protocol; panic if not supported
	prevParams, ok := config.Consensus[prev.CurrentProtocol]
	if !ok {
		err = fmt.Errorf("previous protocol %v not supported", prev.CurrentProtocol)
		return
	}

	// Decide on the votes for protocol upgrades
	upgradeVote := UpgradeVote{}

	// If there is no upgrade proposal, see if we can make one
	if prev.NextProtocol == "" {
		for k, v := range prevParams.ApprovedUpgrades {
			upgradeVote.UpgradePropose = k
			upgradeVote.UpgradeDelay = basics.Round(v)
			upgradeVote.UpgradeApprove = true
			break
		}
	}

	// If there is a proposal being voted on, see if we approve it
	round := prev.Round + 1
	if round < prev.NextProtocolVoteBefore {
		_, ok := prevParams.ApprovedUpgrades[prev.NextProtocol]
		upgradeVote.UpgradeApprove = ok
	}

	upgradeState, err := prev.UpgradeState.applyUpgradeVote(round, upgradeVote)
	if err != nil {
		err = fmt.Errorf("constructed invalid upgrade vote %v for round %v in state %v: %v", upgradeVote, round, prev.UpgradeState, err)
		return
	}

	return upgradeVote, upgradeState, err
}

// MakeBlock constructs a new valid block with an empty payset and an unset Seed.
func MakeBlock(prev BlockHeader) Block {
	upgradeVote, upgradeState, err := ProcessUpgradeParams(prev)
	if err != nil {
		logging.Base().Panicf("MakeBlock: error processing upgrade: %v", err)
	}

	params, ok := config.Consensus[upgradeState.CurrentProtocol]
	if !ok {
		logging.Base().Panicf("MakeBlock: next protocol %v not supported", upgradeState.CurrentProtocol)
	}

	timestamp := time.Now().Unix()
	if prev.TimeStamp > 0 {
		if timestamp < prev.TimeStamp {
			timestamp = prev.TimeStamp
		} else if timestamp > prev.TimeStamp+params.MaxTimestampIncrement {
			timestamp = prev.TimeStamp + params.MaxTimestampIncrement
		}
	}

	// the merkle root of TXs will update when fillpayset is called
	blk := Block{
		BlockHeader: BlockHeader{
			Round:        prev.Round + 1,
			Branch:       prev.Hash(),
			UpgradeVote:  upgradeVote,
			UpgradeState: upgradeState,
			TimeStamp:    timestamp,
			GenesisID:    prev.GenesisID,
			GenesisHash:  prev.GenesisHash,
		},
	}
	blk.TxnRoot, err = blk.PaysetCommit()
	if err != nil {
		logging.Base().Warnf("MakeBlock: computing empty TxnRoot: %v", err)
	}
	return blk
}

// PaysetCommit computes the commitment to the payset, using the appropriate
// commitment plan based on the block's protocol.
func (block Block) PaysetCommit() (crypto.Digest, error) {
	params, ok := config.Consensus[block.CurrentProtocol]
	if !ok {
		return crypto.Digest{}, fmt.Errorf("unsupported protocol %v", block.CurrentProtocol)
	}

	switch params.PaysetCommit {
	case config.PaysetCommitFlat:
		return block.Payset.CommitFlat(), nil
	default:
		return crypto.Digest{}, fmt.Errorf("unsupported payset commit type %d", params.PaysetCommit)
	}
}

// PreCheck checks if the block header bh is a valid successor to
// the previous block's header, prev.
func (bh BlockHeader) PreCheck(prev BlockHeader) error {
	// check protocol
	params, ok := config.Consensus[bh.CurrentProtocol]
	if !ok {
		return fmt.Errorf("BlockHeader.PreCheck: protocol %s not supported", bh.CurrentProtocol)
	}

	// check round
	round := prev.Round + 1
	if round != bh.Round {
		return fmt.Errorf("block round incorrect %v != %v", bh.Round, round)
	}

	// check the pointer to the previous block
	if bh.Branch != prev.Hash() {
		return fmt.Errorf("block branch incorrect %v != %v", bh.Branch, prev.Hash())
	}

	// check upgrade state
	nextUpgradeState, err := prev.UpgradeState.applyUpgradeVote(round, bh.UpgradeVote)
	if err != nil {
		return err
	}
	if nextUpgradeState != bh.UpgradeState {
		return fmt.Errorf("UpgradeState mismatch: %v != %v", nextUpgradeState, bh.UpgradeState)
	}

	// Check timestamp
	// a zero timestamp allows to put whatever time the proposer wants, but since time is monotonic,
	// there can only be a prefix of zeros (or negative) timestamps in the blockchain.
	if prev.TimeStamp > 0 {
		// special case when the previous timestamp is zero -- allow a larger window
		if bh.TimeStamp < prev.TimeStamp {
			return fmt.Errorf("bad timestamp: current %v < previous %v", bh.TimeStamp, prev.TimeStamp)
		} else if bh.TimeStamp > prev.TimeStamp+params.MaxTimestampIncrement {
			return fmt.Errorf("bad timestamp: current %v > previous %v, max increment = %v ", bh.TimeStamp, prev.TimeStamp, params.MaxTimestampIncrement)
		}
	}

	// Check genesis ID value against previous block, if set
	if bh.GenesisID == "" {
		return fmt.Errorf("genesis ID missing")
	}
	if prev.GenesisID != "" && prev.GenesisID != bh.GenesisID {
		return fmt.Errorf("genesis ID mismatch: %s != %s", bh.GenesisID, prev.GenesisID)
	}

	// Check genesis hash value against previous block, if set
	if params.SupportGenesisHash {
		if bh.GenesisHash == (crypto.Digest{}) {
			return fmt.Errorf("genesis hash missing")
		}
		if prev.GenesisHash != (crypto.Digest{}) && prev.GenesisHash != bh.GenesisHash {
			return fmt.Errorf("genesis hash mismatch: %s != %s", bh.GenesisHash, prev.GenesisHash)
		}
	} else {
		if bh.GenesisHash != (crypto.Digest{}) {
			return fmt.Errorf("genesis hash not allowed: %s", bh.GenesisHash)
		}
	}

	return nil
}

// ContentsMatchHeader checks that the TxnRoot matches what's in the header,
// as the header is what the block hash authenticates.
// If we're given an untrusted block and a known-good hash, we can't trust the
// block's transactions unless we validate this.
func (block Block) ContentsMatchHeader() bool {
	expected, err := block.PaysetCommit()
	if err != nil {
		logging.Base().Warnf("ContentsMatchHeader: cannot compute commitment: %v", err)
		return false
	}

	return expected == block.TxnRoot
}

// DecodePaysetGroups decodes block.Payset using DecodeSignedTxn, and returns
// the transactions in groups.
func (block Block) DecodePaysetGroups() ([][]transactions.SignedTxnWithAD, error) {
	var res [][]transactions.SignedTxnWithAD
	var lastGroup []transactions.SignedTxnWithAD
	for _, txib := range block.Payset {
		var err error
		var stxnad transactions.SignedTxnWithAD
		stxnad.SignedTxn, stxnad.ApplyData, err = block.DecodeSignedTxn(txib)
		if err != nil {
			return nil, err
		}

		if lastGroup != nil && (lastGroup[0].SignedTxn.Txn.Group != stxnad.SignedTxn.Txn.Group || lastGroup[0].SignedTxn.Txn.Group.IsZero()) {
			res = append(res, lastGroup)
			lastGroup = nil
		}

		lastGroup = append(lastGroup, stxnad)
	}
	if lastGroup != nil {
		res = append(res, lastGroup)
	}
	return res, nil
}

// DecodePaysetFlat decodes block.Payset using DecodeSignedTxn, and
// flattens groups.
func (block Block) DecodePaysetFlat() ([]transactions.SignedTxnWithAD, error) {
	res := make([]transactions.SignedTxnWithAD, len(block.Payset))
	for i, txib := range block.Payset {
		var err error
		res[i].SignedTxn, res[i].ApplyData, err = block.DecodeSignedTxn(txib)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

// SignedTxnsToGroups splits a slice of SignedTxns into groups.
func SignedTxnsToGroups(txns []transactions.SignedTxn) (res [][]transactions.SignedTxn) {
	var lastGroup []transactions.SignedTxn
	for _, tx := range txns {
		if lastGroup != nil && (lastGroup[0].Txn.Group != tx.Txn.Group || lastGroup[0].Txn.Group.IsZero()) {
			res = append(res, lastGroup)
			lastGroup = nil
		}

		lastGroup = append(lastGroup, tx)
	}
	if lastGroup != nil {
		res = append(res, lastGroup)
	}
	return res
}

// SignedTxnGroupsFlatten combines all groups into a flat slice of SignedTxns.
func SignedTxnGroupsFlatten(txgroups [][]transactions.SignedTxn) (res []transactions.SignedTxn) {
	for _, txgroup := range txgroups {
		res = append(res, txgroup...)
	}
	return res
}

// NextVersionInfo returns information about the next expected protocol version.
// If no upgrade is scheduled, return the current protocol.
func (bh BlockHeader) NextVersionInfo() (ver protocol.ConsensusVersion, rnd basics.Round, supported bool) {
	if bh.Round >= bh.NextProtocolVoteBefore && bh.Round < bh.NextProtocolSwitchOn {
		ver = bh.NextProtocol
		rnd = bh.NextProtocolSwitchOn
	} else {
		ver = bh.CurrentProtocol
		rnd = bh.Round + 1
	}
	_, supported = config.Consensus[ver]
	return
}

// DecodeSignedTxn converts a SignedTxnInBlock from a block to SignedTxn and its
// associated ApplyData.
func (bh BlockHeader) DecodeSignedTxn(stb transactions.SignedTxnInBlock) (transactions.SignedTxn, transactions.ApplyData, error) {
	st := stb.SignedTxn
	ad := stb.ApplyData

	proto := config.Consensus[bh.CurrentProtocol]
	if !proto.SupportSignedTxnInBlock {
		return st, transactions.ApplyData{}, nil
	}

	if st.Txn.GenesisID != "" {
		return transactions.SignedTxn{}, transactions.ApplyData{}, fmt.Errorf("GenesisID <%s> not empty", st.Txn.GenesisID)
	}

	if stb.HasGenesisID {
		st.Txn.GenesisID = bh.GenesisID
	}

	if st.Txn.GenesisHash != (crypto.Digest{}) {
		return transactions.SignedTxn{}, transactions.ApplyData{}, fmt.Errorf("GenesisHash <%v> not empty", st.Txn.GenesisHash)
	}

	if proto.RequireGenesisHash {
		if stb.HasGenesisHash {
			return transactions.SignedTxn{}, transactions.ApplyData{}, fmt.Errorf("HasGenesisHash set to true but RequireGenesisHash obviates the flag")
		}
		st.Txn.GenesisHash = bh.GenesisHash
	} else {
		if stb.HasGenesisHash {
			st.Txn.GenesisHash = bh.GenesisHash
		}
	}

	return st, ad, nil
}

// EncodeSignedTxn converts a SignedTxn and ApplyData into a SignedTxnInBlock
// for that block.
func (bh BlockHeader) EncodeSignedTxn(st transactions.SignedTxn, ad transactions.ApplyData) (transactions.SignedTxnInBlock, error) {
	var stb transactions.SignedTxnInBlock

	proto := config.Consensus[bh.CurrentProtocol]
	if !proto.SupportSignedTxnInBlock {
		stb.SignedTxn = st
		return stb, nil
	}

	if st.Txn.GenesisID != "" {
		if st.Txn.GenesisID == bh.GenesisID {
			st.Txn.GenesisID = ""
			stb.HasGenesisID = true
		} else {
			return transactions.SignedTxnInBlock{}, fmt.Errorf("GenesisID mismatch: %s != %s", st.Txn.GenesisID, bh.GenesisID)
		}
	}

	if (st.Txn.GenesisHash != crypto.Digest{}) {
		if st.Txn.GenesisHash == bh.GenesisHash {
			st.Txn.GenesisHash = crypto.Digest{}
			if !proto.RequireGenesisHash {
				stb.HasGenesisHash = true
			}
		} else {
			return transactions.SignedTxnInBlock{}, fmt.Errorf("GenesisHash mismatch: %v != %v", st.Txn.GenesisHash, bh.GenesisHash)
		}
	} else {
		if proto.RequireGenesisHash {
			return transactions.SignedTxnInBlock{}, fmt.Errorf("GenesisHash required but missing")
		}
	}

	stb.SignedTxn = st
	stb.ApplyData = ad
	return stb, nil
}
