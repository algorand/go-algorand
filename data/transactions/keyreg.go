// Copyright (C) 2019-2025 Algorand, Inc.
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

package transactions

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
)

// KeyregTxnFields captures the fields used for key registration transactions.
type KeyregTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	VotePK           crypto.OneTimeSignatureVerifier `codec:"votekey"`
	SelectionPK      crypto.VRFVerifier              `codec:"selkey"`
	StateProofPK     merklesignature.Commitment      `codec:"sprfkey"`
	VoteFirst        basics.Round                    `codec:"votefst"`
	VoteLast         basics.Round                    `codec:"votelst"`
	VoteKeyDilution  uint64                          `codec:"votekd"`
	Nonparticipation bool                            `codec:"nonpart"`
}

// wellFormed performs some stateless checks on the KeyReg transaction
func (keyreg KeyregTxnFields) wellFormed(header Header, spec SpecialAddresses, proto config.ConsensusParams) error {
	if header.Sender == spec.FeeSink {
		return fmt.Errorf("cannot register participation key for fee sink's address %v", header.Sender)
	}

	if proto.EnableKeyregCoherencyCheck {
		// ensure that the VoteLast is greater or equal to the VoteFirst
		if keyreg.VoteFirst > keyreg.VoteLast {
			return errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound
		}

		// The trio of [VotePK, SelectionPK, VoteKeyDilution] needs to be all zeros or all non-zero for the transaction to be valid.
		if !((keyreg.VotePK.IsEmpty() && keyreg.SelectionPK.IsEmpty() && keyreg.VoteKeyDilution == 0) ||
			(!keyreg.VotePK.IsEmpty() && !keyreg.SelectionPK.IsEmpty() && keyreg.VoteKeyDilution != 0)) {
			return errKeyregTxnNonCoherentVotingKeys
		}

		// if it's a going offline transaction
		if keyreg.VoteKeyDilution == 0 {
			// check that we don't have any VoteFirst/VoteLast fields.
			if keyreg.VoteFirst != 0 || keyreg.VoteLast != 0 {
				return errKeyregTxnOfflineTransactionHasVotingRounds
			}
		} else {
			// going online
			if keyreg.VoteLast == 0 {
				return errKeyregTxnGoingOnlineWithZeroVoteLast
			}
			if keyreg.VoteFirst > header.LastValid+1 {
				return errKeyregTxnGoingOnlineWithFirstVoteAfterLastValid
			}
		}
	}

	// check that, if this tx is marking an account nonparticipating,
	// it supplies no key (as though it were trying to go offline)
	if keyreg.Nonparticipation {
		if !proto.SupportBecomeNonParticipatingTransactions {
			// if the transaction has the Nonparticipation flag high, but the protocol does not support
			// that type of transaction, it is invalid.
			return errKeyregTxnUnsupportedSwitchToNonParticipating
		}
		suppliesNullKeys := keyreg.VotePK.IsEmpty() || keyreg.SelectionPK.IsEmpty()
		if !suppliesNullKeys {
			return errKeyregTxnGoingOnlineWithNonParticipating
		}
	}

	if err := keyreg.stateProofPKWellFormed(proto); err != nil {
		return err
	}

	return nil
}

func (keyreg KeyregTxnFields) stateProofPKWellFormed(proto config.ConsensusParams) error {
	isEmpty := keyreg.StateProofPK.IsEmpty()
	if !proto.EnableStateProofKeyregCheck {
		// make certain empty key is stored.
		if !isEmpty {
			return errKeyregTxnNotEmptyStateProofPK
		}
		return nil
	}

	if proto.MaxKeyregValidPeriod != 0 && uint64(keyreg.VoteLast.SubSaturate(keyreg.VoteFirst)) > proto.MaxKeyregValidPeriod {
		return errKeyRegTxnValidityPeriodTooLong
	}

	if keyreg.Nonparticipation {
		// make certain that set offline request clears the stateProofPK.
		if !isEmpty {
			return errKeyregTxnNonParticipantShouldBeEmptyStateProofPK
		}
		return nil
	}

	if keyreg.VotePK.IsEmpty() || keyreg.SelectionPK.IsEmpty() {
		if !isEmpty {
			return errKeyregTxnOfflineShouldBeEmptyStateProofPK
		}
		return nil
	}

	// online transactions:
	// setting online cannot set an empty stateProofPK
	if isEmpty {
		return errKeyRegEmptyStateProofPK
	}

	return nil
}
