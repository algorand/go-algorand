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

// Balances allow to move MicroAlgos from one address to another and to update balance records, or to access and modify individual balance records
// After a call to Put (or Move), future calls to Get or Move will reflect the updated balance record(s)
type Balances interface {
	// Get looks up the balance record for an address
	// If the account is known to be empty, then err should be nil and the returned balance record should have the given address and empty AccountData
	// A non-nil error means the lookup is impossible (e.g., if the database doesn't have necessary state anymore)
	Get(basics.Address) (basics.BalanceRecord, error)

	Put(basics.BalanceRecord) error

	// Move MicroAlgos from one account to another, doing all necessary overflow checking (convenience method)
	// TODO: Does this need to be part of the balances interface, or can it just be implemented here as a function that calls Put and Get?
	Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards *basics.MicroAlgos, dstRewards *basics.MicroAlgos) error

	// Balances correspond to a Round, which mean that they also correspond
	// to a ConsensusParams.  This returns those parameters.
	ConsensusParams() config.ConsensusParams
}

// Header captures the fields common to every transaction type.
type Header struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sender      basics.Address    `codec:"snd"`
	Fee         basics.MicroAlgos `codec:"fee"`
	FirstValid  basics.Round      `codec:"fv"`
	LastValid   basics.Round      `codec:"lv"`
	Note        []byte            `codec:"note"` // Uniqueness or app-level data about txn
	GenesisID   string            `codec:"gen"`
	GenesisHash crypto.Digest     `codec:"gh"`
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

	// The transaction's Txid is computed when we decode,
	// and cached here, to avoid needlessly recomputing it.
	cachedTxid Txid

	// The valid flag indicates if this transaction was
	// correctly decoded.
	valid bool
}

// ApplyData contains information about the transaction's execution.
type ApplyData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Closing amount for transaction.
	ClosingAmount basics.MicroAlgos `codec:"ca"`

	// Rewards applied to the Sender, Receiver, and CloseRemainderTo accounts.
	SenderRewards   basics.MicroAlgos `codec:"rs"`
	ReceiverRewards basics.MicroAlgos `codec:"rr"`
	CloseRewards    basics.MicroAlgos `codec:"rc"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (tx Transaction) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Transaction, protocol.Encode(tx)
}

func (tx *Transaction) computeID() Txid {
	return Txid(crypto.HashObj(tx))
}

// InitCaches initializes caches inside of Transaction.
func (tx *Transaction) InitCaches() {
	if !tx.valid {
		tx.cachedTxid = tx.computeID()
		tx.valid = true
	}
}

// ResetCaches clears caches inside of Transaction, if the Transaction was modified.
func (tx *Transaction) ResetCaches() {
	tx.valid = false
}

// ID returns the Txid (i.e., hash) of the transaction.
// For efficiency this is precomputed when the Transaction is created.
func (tx Transaction) ID() Txid {
	if tx.valid {
		return tx.cachedTxid
	}
	return tx.computeID()
}

// Sign signs a transaction using a given Account's secrets.
func (tx Transaction) Sign(secrets *crypto.SignatureSecrets) SignedTxn {
	sig := secrets.Sign(tx)

	s := SignedTxn{
		Txn: tx,
		Sig: sig,
	}
	s.InitCaches()
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
func (tx Transaction) MatchAddress(addr basics.Address, spec SpecialAddresses, proto config.ConsensusParams) bool {
	for _, candidate := range tx.RelevantAddrs(spec, proto) {
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
		// All OK

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

	for t, nonZero := range nonZeroFields {
		if nonZero && t != tx.Type {
			return fmt.Errorf("transaction of type %v has non-zero fields for type %v", tx.Type, t)
		}
	}

	if tx.Fee.LessThan(basics.MicroAlgos{Raw: proto.MinTxnFee}) {
		return makeMinFeeErrorf("transaction had fee %v, which is less than the minimum %v", tx.Fee, proto.MinTxnFee)
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
	if tx.Sender == spec.RewardsPool {
		// this check is just to be safe, but reaching here seems impossible, since it requires computing a preimage of rwpool
		return fmt.Errorf("transaction from incentive pool is invalid")
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
func (tx Transaction) RelevantAddrs(spec SpecialAddresses, proto config.ConsensusParams) []basics.Address {
	addrs := []basics.Address{tx.Sender, spec.FeeSink}

	switch tx.Type {
	case protocol.PaymentTx:
		addrs = append(addrs, tx.PaymentTxnFields.Receiver)
		if tx.PaymentTxnFields.CloseRemainderTo != (basics.Address{}) {
			addrs = append(addrs, tx.PaymentTxnFields.CloseRemainderTo)
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

// EstimateEncodedSize returns the estimated encoded size of the transaction including the signature.
// This function is to be used for calculating the fee
func (tx Transaction) EstimateEncodedSize() int {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	keys := crypto.GenerateSignatureSecrets(seed)
	stx := tx.Sign(keys)
	return stx.GetEncodedLength()
}

// Apply changes the balances according to this transaction.
func (tx Transaction) Apply(balances Balances, spec SpecialAddresses) (ad ApplyData, err error) {
	params := balances.ConsensusParams()

	// move fee to pool
	err = balances.Move(tx.Sender, spec.FeeSink, tx.Fee, &ad.SenderRewards, nil)
	if err != nil {
		return
	}

	switch tx.Type {
	case protocol.PaymentTx:
		err = tx.PaymentTxnFields.apply(tx.Header, balances, spec, &ad)

	case protocol.KeyRegistrationTx:
		err = tx.KeyregTxnFields.apply(tx.Header, balances, spec, &ad)

	default:
		err = fmt.Errorf("Unknown transaction type %v", tx.Type)
	}

	// If the protocol does not support rewards in ApplyData,
	// clear them out.
	if !params.RewardsInApplyData {
		ad.SenderRewards = basics.MicroAlgos{}
		ad.ReceiverRewards = basics.MicroAlgos{}
		ad.CloseRewards = basics.MicroAlgos{}
	}

	return
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
