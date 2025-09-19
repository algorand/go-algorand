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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

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

// FromString initializes the Txid from a string
func (txid *Txid) FromString(text string) error {
	d, err := crypto.DigestFromString(text)
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
	Note        []byte            `codec:"note,allocbound=bounds.MaxTxnNoteBytes"` // Uniqueness or app-level data about txn
	GenesisID   string            `codec:"gen,allocbound=bounds.MaxGenesisIDLen"`
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

	// By making HeartbeatTxnFields a pointer we save a ton of space of the
	// Transaction object. Unlike other txn types, the fields will be
	// embedded under a named field in the transaction encoding.
	*HeartbeatTxnFields `codec:"hb"`
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
	// These are populated only when MaxInnerTransactions > 0 (TEAL 5)
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
	TxGroupHashes []crypto.Digest `codec:"txlist,allocbound=bounds.MaxTxGroupSize"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (tg TxGroup) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.TxGroup, protocol.Encode(&tg)
}

// ToBeHashed implements the crypto.Hashable interface.
func (tx Transaction) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Transaction, protocol.Encode(&tx)
}

// txAllocSize returns the max possible size of a transaction without state proof fields.
// It is used to preallocate a buffer for encoding a transaction.
func txAllocSize() int {
	return TransactionMaxSize() - StateProofTxnFieldsMaxSize()
}

// txEncodingPool holds temporary byte slice buffers used for encoding transaction messages.
// Note, it prepends protocol.Transaction tag to the buffer economizing on subsequent append ops.
var txEncodingPool = sync.Pool{
	New: func() interface{} {
		size := txAllocSize() + len(protocol.Transaction)
		buf := make([]byte, len(protocol.Transaction), size)
		copy(buf, []byte(protocol.Transaction))
		return &txEncodingBuf{b: buf}
	},
}

// getTxEncodingBuf returns a wrapped byte slice that can be used for encoding a
// temporary message.  The byte slice length of encoded Transaction{} object.
// The caller gets full ownership of the byte slice,
// but is encouraged to return it using putEncodingBuf().
func getTxEncodingBuf() *txEncodingBuf {
	buf := txEncodingPool.Get().(*txEncodingBuf)
	return buf
}

// putTxEncodingBuf places a byte slice into the pool of temporary buffers
// for encoding.  The caller gives up ownership of the byte slice when
// passing it to putTxEncodingBuf().
func putTxEncodingBuf(buf *txEncodingBuf) {
	buf.b = buf.b[:len(protocol.Transaction)]
	txEncodingPool.Put(buf)
}

type txEncodingBuf struct {
	b []byte
}

// ID returns the Txid (i.e., hash) of the transaction.
func (tx Transaction) ID() Txid {
	buf := getTxEncodingBuf()
	enc := tx.MarshalMsg(buf.b)
	if cap(enc) > cap(buf.b) {
		// use a bigger buffer as New's estimate was too small
		buf.b = enc
	}
	defer putTxEncodingBuf(buf)
	return Txid(crypto.Hash(enc))
}

// IDSha256 returns the digest (i.e., hash) of the transaction.
// This is different from the canonical ID computed with Sum512_256 hashing function.
func (tx Transaction) IDSha256() crypto.Digest {
	buf := getTxEncodingBuf()
	enc := tx.MarshalMsg(buf.b)
	if cap(enc) > cap(buf.b) {
		buf.b = enc
	}
	defer putTxEncodingBuf(buf)
	return sha256.Sum256(enc)
}

// InnerID returns something akin to Txid, but folds in the parent Txid and the
// index of the inner call.
func (tx Transaction) InnerID(parent Txid, index int) Txid {
	buf := getTxEncodingBuf()
	input := append(buf.b, parent[:]...)
	var indexBuf [8]byte
	binary.BigEndian.PutUint64(indexBuf[:], uint64(index))
	input = append(input, indexBuf[:]...)
	enc := tx.MarshalMsg(input)
	if cap(enc) > cap(buf.b) {
		buf.b = enc
	}
	defer putTxEncodingBuf(buf)
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

// MatchAddress checks if the transaction touches a given address.  The feesink
// and rewards pool are not considered matches.
func (tx Transaction) MatchAddress(addr basics.Address) bool {
	if addr == tx.Sender {
		return true
	}

	switch tx.Type {
	case protocol.PaymentTx:
		if addr == tx.PaymentTxnFields.Receiver {
			return true
		}
		if !tx.PaymentTxnFields.CloseRemainderTo.IsZero() &&
			addr == tx.PaymentTxnFields.CloseRemainderTo {
			return true
		}
	case protocol.AssetTransferTx:
		if addr == tx.AssetTransferTxnFields.AssetReceiver {
			return true
		}
		if !tx.AssetTransferTxnFields.AssetCloseTo.IsZero() &&
			addr == tx.AssetTransferTxnFields.AssetCloseTo {
			return true
		}
		if !tx.AssetTransferTxnFields.AssetSender.IsZero() &&
			addr == tx.AssetTransferTxnFields.AssetSender {
			return true
		}
	case protocol.HeartbeatTx:
		if addr == tx.HeartbeatTxnFields.HbAddress {
			return true
		}
	}
	return false
}

// WellFormed checks that the transaction looks reasonable on its own (but not necessarily valid against the actual ledger). It does not check signatures.
func (tx Transaction) WellFormed(spec SpecialAddresses, proto config.ConsensusParams) error {
	switch tx.Type {
	case protocol.PaymentTx:
		err := tx.PaymentTxnFields.wellFormed(tx.Header, spec, proto)
		if err != nil {
			return err
		}

	case protocol.KeyRegistrationTx:
		err := tx.KeyregTxnFields.wellFormed(tx.Header, spec, proto)
		if err != nil {
			return err
		}

	case protocol.AssetConfigTx:
		if !proto.Asset {
			return fmt.Errorf("asset transaction not supported")
		}

		err := tx.AssetConfigTxnFields.wellFormed(proto)
		if err != nil {
			return err
		}

	case protocol.AssetTransferTx:
		if !proto.Asset {
			return fmt.Errorf("asset transaction not supported")
		}

		err := tx.AssetTransferTxnFields.wellFormed()
		if err != nil {
			return err
		}

	case protocol.AssetFreezeTx:
		if !proto.Asset {
			return fmt.Errorf("asset transaction not supported")
		}

		err := tx.AssetFreezeTxnFields.wellFormed()
		if err != nil {
			return err
		}

	case protocol.ApplicationCallTx:
		if !proto.Application {
			return fmt.Errorf("application transaction not supported")
		}

		err := tx.ApplicationCallTxnFields.wellFormed(proto)
		if err != nil {
			return err
		}

	case protocol.StateProofTx:
		if proto.StateProofInterval == 0 {
			return fmt.Errorf("state proofs not supported")
		}

		err := tx.StateProofTxnFields.wellFormed(tx.Header)
		if err != nil {
			return err
		}

	case protocol.HeartbeatTx:
		if !proto.Heartbeat {
			return fmt.Errorf("heartbeat transaction not supported")
		}

		err := tx.HeartbeatTxnFields.wellFormed(tx.Header, proto)
		if err != nil {
			return err
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

	if !tx.StateProofTxnFields.MsgIsZero() {
		nonZeroFields[protocol.StateProofTx] = true
	}

	if tx.HeartbeatTxnFields != nil {
		nonZeroFields[protocol.HeartbeatTx] = true
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
