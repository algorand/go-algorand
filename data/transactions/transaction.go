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

package transactions

import (
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
	CompactCertTxnFields
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
	EvalDelta       basics.EvalDelta  `codec:"dt"`
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
	return Txid(crypto.HashObj(tx))
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
		// check that, if this tx is marking an account nonparticipating,
		// it supplies no key (as though it were trying to go offline)
		if tx.KeyregTxnFields.Nonparticipation {
			if !proto.SupportBecomeNonParticipatingTransactions {
				// if the transaction has the Nonparticipation flag high, but the protocol does not support
				// that type of transaction, it is invalid.
				return fmt.Errorf("transaction tries to mark an account as nonparticipating, but that transaction is not supported")
			}
			suppliesNullKeys := tx.KeyregTxnFields.VotePK == crypto.OneTimeSignatureVerifier{} || tx.KeyregTxnFields.SelectionPK == crypto.VRFVerifier{}
			if !suppliesNullKeys {
				return fmt.Errorf("transaction tries to register keys to go online, but nonparticipatory flag is set")
			}
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
		case NoOpOC:
		case OptInOC:
		case CloseOutOC:
		case ClearStateOC:
		case UpdateApplicationOC:
		case DeleteApplicationOC:
		default:
			return fmt.Errorf("invalid application OnCompletion")
		}

		// Programs may only be set for creation or update
		if tx.ApplicationID != 0 && tx.OnCompletion != UpdateApplicationOC {
			if len(tx.ApprovalProgram) != 0 || len(tx.ClearStateProgram) != 0 {
				return fmt.Errorf("programs may only be specified during application creation or update")
			}
		}

		// Schemas may only be set during application creation
		if tx.ApplicationID != 0 {
			if tx.LocalStateSchema != (basics.StateSchema{}) ||
				tx.GlobalStateSchema != (basics.StateSchema{}) {
				return fmt.Errorf("local and global state schemas are immutable")
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

		if len(tx.ApprovalProgram) > proto.MaxAppProgramLen {
			return fmt.Errorf("approval program too long. max len %d bytes", proto.MaxAppProgramLen)
		}

		if len(tx.ClearStateProgram) > proto.MaxAppProgramLen {
			return fmt.Errorf("clear state program too long. max len %d bytes", proto.MaxAppProgramLen)
		}

		if tx.LocalStateSchema.NumEntries() > proto.MaxLocalSchemaEntries {
			return fmt.Errorf("tx.LocalStateSchema too large, max number of keys is %d", proto.MaxLocalSchemaEntries)
		}

		if tx.GlobalStateSchema.NumEntries() > proto.MaxGlobalSchemaEntries {
			return fmt.Errorf("tx.GlobalStateSchema too large, max number of keys is %d", proto.MaxGlobalSchemaEntries)
		}

	case protocol.CompactCertTx:
		if proto.CompactCertRounds == 0 {
			return fmt.Errorf("compact certs not supported")
		}

		// This is a placeholder transaction used to store compact certs
		// on the ledger, and ensure they are broadly available.  Most of
		// the fields must be empty.  It must be issued from a special
		// sender address.
		if tx.Sender != CompactCertSender {
			return fmt.Errorf("sender must be the compact-cert sender")
		}
		if !tx.Fee.IsZero() {
			return fmt.Errorf("fee must be zero")
		}
		if len(tx.Note) != 0 {
			return fmt.Errorf("note must be empty")
		}
		if !tx.Group.IsZero() {
			return fmt.Errorf("group must be zero")
		}
		if !tx.RekeyTo.IsZero() {
			return fmt.Errorf("rekey must be zero")
		}
		if tx.Lease != [32]byte{} {
			return fmt.Errorf("lease must be zero")
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

	if !tx.CompactCertTxnFields.Empty() {
		nonZeroFields[protocol.CompactCertTx] = true
	}

	for t, nonZero := range nonZeroFields {
		if nonZero && t != tx.Type {
			return fmt.Errorf("transaction of type %v has non-zero fields for type %v", tx.Type, t)
		}
	}

	if tx.Fee.LessThan(basics.MicroAlgos{Raw: proto.MinTxnFee}) {
		if tx.Type == protocol.CompactCertTx {
			// Zero fee allowed for compact cert txn.
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
