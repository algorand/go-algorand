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

package transactions

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// Txid is a hash used to uniquely identify individual transactions
type Txid crypto.Digest

// String converts txid to a pretty-printable string
func (txid Txid) String() string {
	return fmt.Sprintf("%v", crypto.Digest(txid))
}

// UnmarshalText initializes the Address from an array of bytes.
func (txid *Txid) UnmarshalText(text []byte) error {
	d, err := crypto.DigestFromString(string(text))
	*txid = Txid(d)
	return err
}

// SpecialAddresses holds addresses with nonstandard properties.
type SpecialAddresses struct {
	FeeSink     basics.Address
	RewardsPool basics.Address
}

// Header captures the fields common to every transaction type.
type Header struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sender      basics.Address    `codec:"snd"`
	Fee         basics.MicroAlgos `codec:"fee"`
	FirstValid  basics.Round      `codec:"fv"`
	LastValid   basics.Round      `codec:"lv"`
	Note        []byte            `codec:"note,allocbound=config.MaxTxnNoteBytes"` // Uniqueness or app-level data about txn
	GenesisID   string            `codec:"gen"`
	GenesisHash crypto.Digest     `codec:"gh"`

	// Group specifies that this transaction is part of a
	// transaction group (and, if so, specifies the hash
	// of a TxGroup).
	Group crypto.Digest `codec:"grp"`

	// Lease enforces mutual exclusion of transactions.  If this field is
	// nonzero, then once the transaction is confirmed, it acquires the
	// lease identified by the (Sender, Lease) pair of the transaction until
	// the LastValid round passes.  While this transaction possesses the
	// lease, no other transaction specifying this lease can be confirmed.
	Lease [32]byte `codec:"lx"`

	// RekeyTo, if nonzero, sets the sender's AuthAddr to the given address
	// If the RekeyTo address is the sender's actual address, the AuthAddr is set to zero
	// This allows "re-keying" a long-lived account -- rotating the signing key, changing
	// membership of a multisig account, etc.
	RekeyTo basics.Address `codec:"rekey"`
}

// Transaction describes a transaction that can appear in a block.
type Transaction struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Type of transaction
	Type protocol.TxType `codec:"type"`

	// Common fields for all types of transactions
	Header

	// Fields for different types of transactions
	KeyregTxnFields
	PaymentTxnFields
	AssetConfigTxnFields
	AssetTransferTxnFields
	AssetFreezeTxnFields
	ApplicationCallTxnFields
	StateProofTxnFields
}

// ApplyData contains information about the transaction's execution.
type ApplyData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Closing amount for transaction.
	ClosingAmount basics.MicroAlgos `codec:"ca"`

	// Closing amount for asset transaction.
	AssetClosingAmount uint64 `codec:"aca"`

	// Rewards applied to the Sender, Receiver, and CloseRemainderTo accounts.
	SenderRewards   basics.MicroAlgos `codec:"rs"`
	ReceiverRewards basics.MicroAlgos `codec:"rr"`
	CloseRewards    basics.MicroAlgos `codec:"rc"`
	EvalDelta       EvalDelta         `codec:"dt"`

	// If asa or app is being created, the id used. Else 0.
	// Names chosen to match naming the corresponding txn.
	// These are populated on when MaxInnerTransactions > 0 (TEAL 5)
	ConfigAsset   basics.AssetIndex `codec:"caid"`
	ApplicationID basics.AppIndex   `codec:"apid"`
}

// Equal returns true if two ApplyDatas are equal, ignoring nilness equality on
// EvalDelta's internal deltas (see EvalDelta.Equal for more information)
func (ad ApplyData) Equal(o ApplyData) bool {
	if ad.ClosingAmount != o.ClosingAmount {
		return false
	}
	if ad.AssetClosingAmount != o.AssetClosingAmount {
		return false
	}
	if ad.SenderRewards != o.SenderRewards {
		return false
	}
	if ad.ReceiverRewards != o.ReceiverRewards {
		return false
	}
	if ad.CloseRewards != o.CloseRewards {
		return false
	}
	if ad.ConfigAsset != o.ConfigAsset {
		return false
	}
	if ad.ApplicationID != o.ApplicationID {
		return false
	}
	if !ad.EvalDelta.Equal(o.EvalDelta) {
		return false
	}
	return true
}

// TxGroup describes a group of transactions that must appear
// together in a specific order in a block.
type TxGroup struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// TxGroupHashes specifies a list of hashes of transactions that must appear
	// together, sequentially, in a block in order for the group to be
	// valid.  Each hash in the list is a hash of a transaction with
	// the `Group` field omitted.
	// These are all `Txid` which is equivalent to `crypto.Digest`
	TxGroupHashes []crypto.Digest `codec:"txlist,allocbound=config.MaxTxGroupSize"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (tg TxGroup) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.TxGroup, protocol.Encode(&tg)
}

// ToBeHashed implements the crypto.Hashable interface.
func (tx Transaction) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Transaction, protocol.Encode(&tx)
}

// ID returns the Txid (i.e., hash) of the transaction.
func (tx Transaction) ID() Txid {
	enc := tx.MarshalMsg(append(protocol.GetEncodingBuf(), []byte(protocol.Transaction)...))
	defer protocol.PutEncodingBuf(enc)
	return Txid(crypto.Hash(enc))
}

// IDSha256 returns the digest (i.e., hash) of the transaction.
func (tx Transaction) IDSha256() crypto.Digest {
	enc := tx.MarshalMsg(append(protocol.GetEncodingBuf(), []byte(protocol.Transaction)...))
	defer protocol.PutEncodingBuf(enc)
	return sha256.Sum256(enc)
}

// InnerID returns something akin to Txid, but folds in the parent Txid and the
// index of the inner call.
func (tx Transaction) InnerID(parent Txid, index int) Txid {
	input := append(protocol.GetEncodingBuf(), []byte(protocol.Transaction)...)
	input = append(input, parent[:]...)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(index))
	input = append(input, buf...)
	enc := tx.MarshalMsg(input)
	defer protocol.PutEncodingBuf(enc)
	return Txid(crypto.Hash(enc))
}

// Sign signs a transaction using a given Account's secrets.
func (tx Transaction) Sign(secrets *crypto.SignatureSecrets) SignedTxn {
	sig := secrets.Sign(tx)

	s := SignedTxn{
		Txn: tx,
		Sig: sig,
	}
	// Set the AuthAddr if the signing key doesn't match the transaction sender
	if basics.Address(secrets.SignatureVerifier) != tx.Sender {
		s.AuthAddr = basics.Address(secrets.SignatureVerifier)
	}
	return s
}

// Src returns the address that posted the transaction.
// This is the account that pays the associated Fee.
func (tx Header) Src() basics.Address {
	return tx.Sender
}

// TxFee returns the fee associated with this transaction.
func (tx Header) TxFee() basics.MicroAlgos {
	return tx.Fee
}

// Alive checks to see if the transaction is still alive (can be applied) at the specified Round.
func (tx Header) Alive(tc TxnContext) error {
	// Check round validity
	round := tc.Round()
	if round < tx.FirstValid || round > tx.LastValid {
		return TxnDeadError{
			Round:      round,
			FirstValid: tx.FirstValid,
			LastValid:  tx.LastValid,
		}
	}

	// Check genesis ID
	proto := tc.ConsensusProtocol()
	genesisID := tc.GenesisID()
	if tx.GenesisID != "" && tx.GenesisID != genesisID {
		return fmt.Errorf("tx.GenesisID <%s> does not match expected <%s>",
			tx.GenesisID, genesisID)
	}

	// Check genesis hash
	if proto.SupportGenesisHash {
		genesisHash := tc.GenesisHash()
		if tx.GenesisHash != (crypto.Digest{}) && tx.GenesisHash != genesisHash {
			return fmt.Errorf("tx.GenesisHash <%s> does not match expected <%s>",
				tx.GenesisHash, genesisHash)
		}
		if proto.RequireGenesisHash && tx.GenesisHash == (crypto.Digest{}) {
			return fmt.Errorf("required tx.GenesisHash is missing")
		}
	} else {
		if tx.GenesisHash != (crypto.Digest{}) {
			return fmt.Errorf("tx.GenesisHash <%s> not allowed", tx.GenesisHash)
		}
	}

	return nil
}

// MatchAddress checks if the transaction touches a given address.
func (tx Transaction) MatchAddress(addr basics.Address, spec SpecialAddresses) bool {
	for _, candidate := range tx.RelevantAddrs(spec) {
		if addr == candidate {
			return true
		}
	}
	return false
}

var errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound = errors.New("transaction first voting round need to be less than its last voting round")
var errKeyregTxnNonCoherentVotingKeys = errors.New("the following transaction fields need to be clear/set together : votekey, selkey, votekd")
var errKeyregTxnOfflineTransactionHasVotingRounds = errors.New("on going offline key registration transaction, the vote first and vote last fields should not be set")
var errKeyregTxnUnsupportedSwitchToNonParticipating = errors.New("transaction tries to mark an account as nonparticipating, but that transaction is not supported")
var errKeyregTxnGoingOnlineWithNonParticipating = errors.New("transaction tries to register keys to go online, but nonparticipatory flag is set")
var errKeyregTxnGoingOnlineWithZeroVoteLast = errors.New("transaction tries to register keys to go online, but vote last is set to zero")
var errKeyregTxnGoingOnlineWithFirstVoteAfterLastValid = errors.New("transaction tries to register keys to go online, but first voting round is beyond the round after last valid round")
var errKeyRegEmptyStateProofPK = errors.New("online keyreg transaction cannot have empty field StateProofPK")
var errKeyregTxnNotEmptyStateProofPK = errors.New("transaction field StateProofPK should be empty in this consensus version")
var errKeyregTxnNonParticipantShouldBeEmptyStateProofPK = errors.New("non participation keyreg transactions should contain empty stateProofPK")
var errKeyregTxnOfflineShouldBeEmptyStateProofPK = errors.New("offline keyreg transactions should contain empty stateProofPK")
var errKeyRegTxnValidityPeriodTooLong = errors.New("validity period for keyreg transaction is too long")
var errStateProofNotSupported = errors.New("state proofs not supported")
var errBadSenderInStateProofTxn = errors.New("sender must be the state-proof sender")
var errFeeMustBeZeroInStateproofTxn = errors.New("fee must be zero in state-proof transaction")
var errNoteMustBeEmptyInStateproofTxn = errors.New("note must be empty in state-proof transaction")
var errGroupMustBeZeroInStateproofTxn = errors.New("group must be zero in state-proof transaction")
var errRekeyToMustBeZeroInStateproofTxn = errors.New("rekey must be zero in state-proof transaction")
var errLeaseMustBeZeroInStateproofTxn = errors.New("lease must be zero in state-proof transaction")

// WellFormed checks that the transaction looks reasonable on its own (but not necessarily valid against the actual ledger). It does not check signatures.
func (tx Transaction) WellFormed(spec SpecialAddresses, proto config.ConsensusParams) error {
	switch tx.Type {
	case protocol.PaymentTx:
		// in case that the fee sink is spending, check that this spend is to a valid address
		err := tx.checkSpender(tx.Header, spec, proto)
		if err != nil {
			return err
		}

	case protocol.KeyRegistrationTx:
		if proto.EnableKeyregCoherencyCheck {
			// ensure that the VoteLast is greater or equal to the VoteFirst
			if tx.KeyregTxnFields.VoteFirst > tx.KeyregTxnFields.VoteLast {
				return errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound
			}

			// The trio of [VotePK, SelectionPK, VoteKeyDilution] needs to be all zeros or all non-zero for the transaction to be valid.
			if !((tx.KeyregTxnFields.VotePK == crypto.OneTimeSignatureVerifier{} && tx.KeyregTxnFields.SelectionPK == crypto.VRFVerifier{} && tx.KeyregTxnFields.VoteKeyDilution == 0) ||
				(tx.KeyregTxnFields.VotePK != crypto.OneTimeSignatureVerifier{} && tx.KeyregTxnFields.SelectionPK != crypto.VRFVerifier{} && tx.KeyregTxnFields.VoteKeyDilution != 0)) {
				return errKeyregTxnNonCoherentVotingKeys
			}

			// if it's a going offline transaction
			if tx.KeyregTxnFields.VoteKeyDilution == 0 {
				// check that we don't have any VoteFirst/VoteLast fields.
				if tx.KeyregTxnFields.VoteFirst != 0 || tx.KeyregTxnFields.VoteLast != 0 {
					return errKeyregTxnOfflineTransactionHasVotingRounds
				}
			} else {
				// going online
				if tx.KeyregTxnFields.VoteLast == 0 {
					return errKeyregTxnGoingOnlineWithZeroVoteLast
				}
				if tx.KeyregTxnFields.VoteFirst > tx.LastValid+1 {
					return errKeyregTxnGoingOnlineWithFirstVoteAfterLastValid
				}
			}
		}

		// check that, if this tx is marking an account nonparticipating,
		// it supplies no key (as though it were trying to go offline)
		if tx.KeyregTxnFields.Nonparticipation {
			if !proto.SupportBecomeNonParticipatingTransactions {
				// if the transaction has the Nonparticipation flag high, but the protocol does not support
				// that type of transaction, it is invalid.
				return errKeyregTxnUnsupportedSwitchToNonParticipating
			}
			suppliesNullKeys := tx.KeyregTxnFields.VotePK == crypto.OneTimeSignatureVerifier{} || tx.KeyregTxnFields.SelectionPK == crypto.VRFVerifier{}
			if !suppliesNullKeys {
				return errKeyregTxnGoingOnlineWithNonParticipating
			}
		}

		if err := tx.stateProofPKWellFormed(proto); err != nil {
			return err
		}

	case protocol.AssetConfigTx:
		if !proto.Asset {
			return fmt.Errorf("asset transaction not supported")
		}

	case protocol.AssetTransferTx:
		if !proto.Asset {
			return fmt.Errorf("asset transaction not supported")
		}

	case protocol.AssetFreezeTx:
		if !proto.Asset {
			return fmt.Errorf("asset transaction not supported")
		}
	case protocol.ApplicationCallTx:
		if !proto.Application {
			return fmt.Errorf("application transaction not supported")
		}

		// Ensure requested action is valid
		switch tx.OnCompletion {
		case NoOpOC, OptInOC, CloseOutOC, ClearStateOC, UpdateApplicationOC, DeleteApplicationOC:
			/* ok */
		default:
			return fmt.Errorf("invalid application OnCompletion")
		}

		// Programs may only be set for creation or update
		if tx.ApplicationID != 0 && tx.OnCompletion != UpdateApplicationOC {
			if len(tx.ApprovalProgram) != 0 || len(tx.ClearStateProgram) != 0 {
				return fmt.Errorf("programs may only be specified during application creation or update")
			}
		} else {
			// This will check version matching, but not downgrading. That
			// depends on chain state (so we pass an empty AppParams)
			err := CheckContractVersions(tx.ApprovalProgram, tx.ClearStateProgram, basics.AppParams{}, &proto)
			if err != nil {
				return err
			}
		}

		effectiveEPP := tx.ExtraProgramPages
		// Schemas and ExtraProgramPages may only be set during application creation
		if tx.ApplicationID != 0 {
			if tx.LocalStateSchema != (basics.StateSchema{}) ||
				tx.GlobalStateSchema != (basics.StateSchema{}) {
				return fmt.Errorf("local and global state schemas are immutable")
			}
			if tx.ExtraProgramPages != 0 {
				return fmt.Errorf("tx.ExtraProgramPages is immutable")
			}

			if proto.EnableExtraPagesOnAppUpdate {
				effectiveEPP = uint32(proto.MaxExtraAppProgramPages)
			}

		}

		// Limit total number of arguments
		if len(tx.ApplicationArgs) > proto.MaxAppArgs {
			return fmt.Errorf("too many application args, max %d", proto.MaxAppArgs)
		}

		// Sum up argument lengths
		var argSum uint64
		for _, arg := range tx.ApplicationArgs {
			argSum = basics.AddSaturate(argSum, uint64(len(arg)))
		}

		// Limit total length of all arguments
		if argSum > uint64(proto.MaxAppTotalArgLen) {
			return fmt.Errorf("application args total length too long, max len %d bytes", proto.MaxAppTotalArgLen)
		}

		// Limit number of accounts referred to in a single ApplicationCall
		if len(tx.Accounts) > proto.MaxAppTxnAccounts {
			return fmt.Errorf("tx.Accounts too long, max number of accounts is %d", proto.MaxAppTxnAccounts)
		}

		// Limit number of other app global states referred to
		if len(tx.ForeignApps) > proto.MaxAppTxnForeignApps {
			return fmt.Errorf("tx.ForeignApps too long, max number of foreign apps is %d", proto.MaxAppTxnForeignApps)
		}

		if len(tx.ForeignAssets) > proto.MaxAppTxnForeignAssets {
			return fmt.Errorf("tx.ForeignAssets too long, max number of foreign assets is %d", proto.MaxAppTxnForeignAssets)
		}

		if len(tx.Boxes) > proto.MaxAppBoxReferences {
			return fmt.Errorf("tx.Boxes too long, max number of box references is %d", proto.MaxAppBoxReferences)
		}

		// Limit the sum of all types of references that bring in account records
		if len(tx.Accounts)+len(tx.ForeignApps)+len(tx.ForeignAssets)+len(tx.Boxes) > proto.MaxAppTotalTxnReferences {
			return fmt.Errorf("tx references exceed MaxAppTotalTxnReferences = %d", proto.MaxAppTotalTxnReferences)
		}

		if tx.ExtraProgramPages > uint32(proto.MaxExtraAppProgramPages) {
			return fmt.Errorf("tx.ExtraProgramPages exceeds MaxExtraAppProgramPages = %d", proto.MaxExtraAppProgramPages)
		}

		lap := len(tx.ApprovalProgram)
		lcs := len(tx.ClearStateProgram)
		pages := int(1 + effectiveEPP)
		if lap > pages*proto.MaxAppProgramLen {
			return fmt.Errorf("approval program too long. max len %d bytes", pages*proto.MaxAppProgramLen)
		}
		if lcs > pages*proto.MaxAppProgramLen {
			return fmt.Errorf("clear state program too long. max len %d bytes", pages*proto.MaxAppProgramLen)
		}
		if lap+lcs > pages*proto.MaxAppTotalProgramLen {
			return fmt.Errorf("app programs too long. max total len %d bytes", pages*proto.MaxAppTotalProgramLen)
		}

		for i, br := range tx.Boxes {
			// recall 0 is the current app so indexes are shifted, thus test is for greater than, not gte.
			if br.Index > uint64(len(tx.ForeignApps)) {
				return fmt.Errorf("tx.Boxes[%d].Index is %d. Exceeds len(tx.ForeignApps)", i, br.Index)
			}
		}

		if tx.LocalStateSchema.NumEntries() > proto.MaxLocalSchemaEntries {
			return fmt.Errorf("tx.LocalStateSchema too large, max number of keys is %d", proto.MaxLocalSchemaEntries)
		}

		if tx.GlobalStateSchema.NumEntries() > proto.MaxGlobalSchemaEntries {
			return fmt.Errorf("tx.GlobalStateSchema too large, max number of keys is %d", proto.MaxGlobalSchemaEntries)
		}

	case protocol.StateProofTx:
		if proto.StateProofInterval == 0 {
			return errStateProofNotSupported
		}

		// This is a placeholder transaction used to store state proofs
		// on the ledger, and ensure they are broadly available.  Most of
		// the fields must be empty.  It must be issued from a special
		// sender address.
		if tx.Sender != StateProofSender {
			return errBadSenderInStateProofTxn
		}
		if !tx.Fee.IsZero() {
			return errFeeMustBeZeroInStateproofTxn
		}
		if len(tx.Note) != 0 {
			return errNoteMustBeEmptyInStateproofTxn
		}
		if !tx.Group.IsZero() {
			return errGroupMustBeZeroInStateproofTxn
		}
		if !tx.RekeyTo.IsZero() {
			return errRekeyToMustBeZeroInStateproofTxn
		}
		if tx.Lease != [32]byte{} {
			return errLeaseMustBeZeroInStateproofTxn
		}

	default:
		return fmt.Errorf("unknown tx type %v", tx.Type)
	}

	nonZeroFields := make(map[protocol.TxType]bool)
	if tx.PaymentTxnFields != (PaymentTxnFields{}) {
		nonZeroFields[protocol.PaymentTx] = true
	}

	if tx.KeyregTxnFields != (KeyregTxnFields{}) {
		nonZeroFields[protocol.KeyRegistrationTx] = true
	}

	if tx.AssetConfigTxnFields != (AssetConfigTxnFields{}) {
		nonZeroFields[protocol.AssetConfigTx] = true
	}

	if tx.AssetTransferTxnFields != (AssetTransferTxnFields{}) {
		nonZeroFields[protocol.AssetTransferTx] = true
	}

	if tx.AssetFreezeTxnFields != (AssetFreezeTxnFields{}) {
		nonZeroFields[protocol.AssetFreezeTx] = true
	}

	if !tx.ApplicationCallTxnFields.Empty() {
		nonZeroFields[protocol.ApplicationCallTx] = true
	}

	if !tx.StateProofTxnFields.Empty() {
		nonZeroFields[protocol.StateProofTx] = true
	}

	for t, nonZero := range nonZeroFields {
		if nonZero && t != tx.Type {
			return fmt.Errorf("transaction of type %v has non-zero fields for type %v", tx.Type, t)
		}
	}

	if !proto.EnableFeePooling && tx.Fee.LessThan(basics.MicroAlgos{Raw: proto.MinTxnFee}) {
		if tx.Type == protocol.StateProofTx {
			// Zero fee allowed for stateProof txn.
		} else {
			return makeMinFeeErrorf("transaction had fee %d, which is less than the minimum %d", tx.Fee.Raw, proto.MinTxnFee)
		}
	}
	if tx.LastValid < tx.FirstValid {
		return fmt.Errorf("transaction invalid range (%v--%v)", tx.FirstValid, tx.LastValid)
	}
	if tx.LastValid-tx.FirstValid > basics.Round(proto.MaxTxnLife) {
		return fmt.Errorf("transaction window size excessive (%v--%v)", tx.FirstValid, tx.LastValid)
	}
	if len(tx.Note) > proto.MaxTxnNoteBytes {
		return fmt.Errorf("transaction note too big: %d > %d", len(tx.Note), proto.MaxTxnNoteBytes)
	}
	if len(tx.AssetConfigTxnFields.AssetParams.AssetName) > proto.MaxAssetNameBytes {
		return fmt.Errorf("transaction asset name too big: %d > %d", len(tx.AssetConfigTxnFields.AssetParams.AssetName), proto.MaxAssetNameBytes)
	}
	if len(tx.AssetConfigTxnFields.AssetParams.UnitName) > proto.MaxAssetUnitNameBytes {
		return fmt.Errorf("transaction asset unit name too big: %d > %d", len(tx.AssetConfigTxnFields.AssetParams.UnitName), proto.MaxAssetUnitNameBytes)
	}
	if len(tx.AssetConfigTxnFields.AssetParams.URL) > proto.MaxAssetURLBytes {
		return fmt.Errorf("transaction asset url too big: %d > %d", len(tx.AssetConfigTxnFields.AssetParams.URL), proto.MaxAssetURLBytes)
	}
	if tx.AssetConfigTxnFields.AssetParams.Decimals > proto.MaxAssetDecimals {
		return fmt.Errorf("transaction asset decimals is too high (max is %d)", proto.MaxAssetDecimals)
	}
	if tx.Sender == spec.RewardsPool {
		// this check is just to be safe, but reaching here seems impossible, since it requires computing a preimage of rwpool
		return fmt.Errorf("transaction from incentive pool is invalid")
	}
	if tx.Sender.IsZero() {
		return fmt.Errorf("transaction cannot have zero sender")
	}
	if !proto.SupportTransactionLeases && (tx.Lease != [32]byte{}) {
		return fmt.Errorf("transaction tried to acquire lease %v but protocol does not support transaction leases", tx.Lease)
	}
	if !proto.SupportTxGroups && (tx.Group != crypto.Digest{}) {
		return fmt.Errorf("transaction has group but groups not yet enabled")
	}
	if !proto.SupportRekeying && (tx.RekeyTo != basics.Address{}) {
		return fmt.Errorf("transaction has RekeyTo set but rekeying not yet enabled")
	}
	return nil
}

func (tx Transaction) stateProofPKWellFormed(proto config.ConsensusParams) error {
	isEmpty := tx.KeyregTxnFields.StateProofPK.IsEmpty()
	if !proto.EnableStateProofKeyregCheck {
		// make certain empty key is stored.
		if !isEmpty {
			return errKeyregTxnNotEmptyStateProofPK
		}
		return nil
	}

	if proto.MaxKeyregValidPeriod != 0 && uint64(tx.VoteLast.SubSaturate(tx.VoteFirst)) > proto.MaxKeyregValidPeriod {
		return errKeyRegTxnValidityPeriodTooLong
	}

	if tx.Nonparticipation {
		// make certain that set offline request clears the stateProofPK.
		if !isEmpty {
			return errKeyregTxnNonParticipantShouldBeEmptyStateProofPK
		}
		return nil
	}

	if tx.VotePK == (crypto.OneTimeSignatureVerifier{}) || tx.SelectionPK == (crypto.VRFVerifier{}) {
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

// Aux returns the note associated with this transaction
func (tx Header) Aux() []byte {
	return tx.Note
}

// First returns the first round this transaction is valid
func (tx Header) First() basics.Round {
	return tx.FirstValid
}

// Last returns the first round this transaction is valid
func (tx Header) Last() basics.Round {
	return tx.LastValid
}

// RelevantAddrs returns the addresses whose balance records this transaction will need to access.
// The header's default is to return just the sender and the fee sink.
func (tx Transaction) RelevantAddrs(spec SpecialAddresses) []basics.Address {
	addrs := []basics.Address{tx.Sender, spec.FeeSink}

	switch tx.Type {
	case protocol.PaymentTx:
		addrs = append(addrs, tx.PaymentTxnFields.Receiver)
		if !tx.PaymentTxnFields.CloseRemainderTo.IsZero() {
			addrs = append(addrs, tx.PaymentTxnFields.CloseRemainderTo)
		}
	case protocol.AssetTransferTx:
		addrs = append(addrs, tx.AssetTransferTxnFields.AssetReceiver)
		if !tx.AssetTransferTxnFields.AssetCloseTo.IsZero() {
			addrs = append(addrs, tx.AssetTransferTxnFields.AssetCloseTo)
		}
		if !tx.AssetTransferTxnFields.AssetSender.IsZero() {
			addrs = append(addrs, tx.AssetTransferTxnFields.AssetSender)
		}
	}

	return addrs
}

// TxAmount returns the amount paid to the recipient in this payment
func (tx Transaction) TxAmount() basics.MicroAlgos {
	switch tx.Type {
	case protocol.PaymentTx:
		return tx.PaymentTxnFields.Amount

	default:
		return basics.MicroAlgos{Raw: 0}
	}
}

// GetReceiverAddress returns the address of the receiver. If the transaction has no receiver, it returns the empty address.
func (tx Transaction) GetReceiverAddress() basics.Address {
	switch tx.Type {
	case protocol.PaymentTx:
		return tx.PaymentTxnFields.Receiver
	case protocol.AssetTransferTx:
		return tx.AssetTransferTxnFields.AssetReceiver
	default:
		return basics.Address{}
	}
}

// EstimateEncodedSize returns the estimated encoded size of the transaction including the signature.
// This function is to be used for calculating the fee
// Note that it may be an underestimate if the transaction is signed in an unusual way
// (e.g., with an authaddr or via multisig or logicsig)
func (tx Transaction) EstimateEncodedSize() int {
	// Make a signedtxn with a nonzero signature and encode it
	stx := SignedTxn{
		Txn: tx,
		Sig: crypto.Signature{1},
	}
	return stx.GetEncodedLength()
}

// TxnContext describes the context in which a transaction can appear
// (pretty much, a block, but we don't have the definition of a block
// here, since that would be a circular dependency).  This is used to
// decide if a transaction is alive or not.
type TxnContext interface {
	Round() basics.Round
	ConsensusProtocol() config.ConsensusParams
	GenesisID() string
	GenesisHash() crypto.Digest
}

// ProgramVersion extracts the version of an AVM program from its bytecode
func ProgramVersion(bytecode []byte) (version uint64, length int, err error) {
	if len(bytecode) == 0 {
		return 0, 0, errors.New("invalid program (empty)")
	}
	version, vlen := binary.Uvarint(bytecode)
	if vlen <= 0 {
		return 0, 0, errors.New("invalid version")
	}
	return version, vlen, nil
}

// syncProgramsVersion is version of AVM programs that are required to have
// matching versions between approval and clearstate.
const syncProgramsVersion = 6

// CheckContractVersions ensures that for syncProgramsVersion and higher, two programs are version
// matched, and that they are not a downgrade.  If either program version is
// >= proto.MinInnerApplVersion, downgrade of that program is not allowed.
func CheckContractVersions(approval []byte, clear []byte, previous basics.AppParams, proto *config.ConsensusParams) error {
	av, _, err := ProgramVersion(approval)
	if err != nil {
		return fmt.Errorf("bad ApprovalProgram: %v", err)
	}
	cv, _, err := ProgramVersion(clear)
	if err != nil {
		return fmt.Errorf("bad ClearStateProgram: %v", err)
	}
	if av >= syncProgramsVersion || cv >= syncProgramsVersion {
		if av != cv {
			return fmt.Errorf("program version mismatch: %d != %d", av, cv)
		}
	}
	// The downgrade check ensures that if app A opts its account into app B
	// (which requires B's CSP to be a callable version), the CSP will STAY
	// callable. That way, A can certainly ClearState its account out of B.
	if len(previous.ApprovalProgram) != 0 { // in creation and in call from WellFormed() previous is empty
		pav, _, err := ProgramVersion(previous.ApprovalProgram)
		if err != nil {
			return err
		}
		if pav >= proto.MinInnerApplVersion && av < pav {
			return fmt.Errorf("approval program version downgrade: %d < %d", av, pav)
		}
	}
	if len(previous.ClearStateProgram) != 0 {
		pcv, _, err := ProgramVersion(previous.ClearStateProgram)
		if err != nil {
			return err
		}
		if pcv >= proto.MinInnerApplVersion && cv < pcv {
			return fmt.Errorf("clearstate program version downgrade: %d < %d", cv, pcv)
		}
	}
	return nil
}

// ExplicitTxnContext is a struct that implements TxnContext with
// explicit fields for everything.
type ExplicitTxnContext struct {
	ExplicitRound basics.Round
	Proto         config.ConsensusParams
	GenID         string
	GenHash       crypto.Digest
}

// Round implements the TxnContext interface
func (tc ExplicitTxnContext) Round() basics.Round {
	return tc.ExplicitRound
}

// ConsensusProtocol implements the TxnContext interface
func (tc ExplicitTxnContext) ConsensusProtocol() config.ConsensusParams {
	return tc.Proto
}

// GenesisID implements the TxnContext interface
func (tc ExplicitTxnContext) GenesisID() string {
	return tc.GenID
}

// GenesisHash implements the TxnContext interface
func (tc ExplicitTxnContext) GenesisHash() crypto.Digest {
	return tc.GenHash
}
