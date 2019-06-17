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

package main

import (
	"fmt"
	"reflect"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// inspectSignedTxn is isomorphic to SignedTxn but uses different
// types to print public keys using algorand's address format
// (base32 + checksum) in JSON, instead of the default base64.
type inspectSignedTxn struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sig  crypto.Signature   `codec:"sig"`
	Msig inspectMultisigSig `codec:"msig"`
	Txn  inspectTransaction `codec:"txn"`
}

// inspectMultisigSig is isomorphic to MultisigSig but uses different
// types to print public keys using algorand's address format in JSON.
type inspectMultisigSig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Version   uint8                   `codec:"v"`
	Threshold uint8                   `codec:"thr"`
	Subsigs   []inspectMultisigSubsig `codec:"subsig"`
}

// inspectMultisigSig is isomorphic to MultisigSig but uses different
// types to print public keys using algorand's address format in JSON.
type inspectMultisigSubsig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Key checksumAddress  `codec:"pk"`
	Sig crypto.Signature `codec:"s"`
}

// inspectTransaction is isomorphic to Transaction but uses different
// types to print public keys using algorand's address format in JSON.
type inspectTransaction struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Type protocol.TxType `codec:"type"`
	inspectTxnHeader
	transactions.KeyregTxnFields
	inspectPaymentTxnFields
}

// inspectTxnHeader is isomorphic to Header but uses different
// types to print public keys using algorand's address format in JSON.
type inspectTxnHeader struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sender      checksumAddress   `codec:"snd"`
	Fee         basics.MicroAlgos `codec:"fee"`
	FirstValid  basics.Round      `codec:"fv"`
	LastValid   basics.Round      `codec:"lv"`
	Note        []byte            `codec:"note"`
	GenesisID   string            `codec:"gen"`
	GenesisHash crypto.Digest     `codec:"gh"`
}

// inspectPaymentTxnFields is isomorphic to Header but uses different
// types to print public keys using algorand's address format in JSON.
type inspectPaymentTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Receiver         checksumAddress   `codec:"rcv"`
	Amount           basics.MicroAlgos `codec:"amt"`
	CloseRemainderTo checksumAddress   `codec:"close"`
}

// checksumAddress is a checksummed address, for use with text encodings
// like JSON.
type checksumAddress basics.Address

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (a *checksumAddress) UnmarshalText(text []byte) error {
	addr, err := basics.UnmarshalChecksumAddress(string(text))
	if err != nil {
		return err
	}

	*a = checksumAddress(addr)
	return nil
}

// MarshalText implements the encoding.TextMarshaler interface
func (a checksumAddress) MarshalText() (text []byte, err error) {
	addr := basics.Address(a)
	return []byte(addr.GetChecksumAddress().String()), nil
}

func inspectTxn(stxn transactions.SignedTxn) (sti inspectSignedTxn, err error) {
	sti = stxnToInspect(stxn)
	if !reflect.DeepEqual(stxn, stxnFromInspect(sti)) {
		err = fmt.Errorf("non-idempotent transformation to inspectSignedTxn (DeepEqual)")
		return
	}
	if !reflect.DeepEqual(protocol.Encode(sti), protocol.Encode(stxn)) {
		err = fmt.Errorf("non-idempotent transformation to inspectSignedTxn (protocol.Encode)")
		return
	}
	return
}

func stxnToInspect(stxn transactions.SignedTxn) inspectSignedTxn {
	return inspectSignedTxn{
		Txn:  txnToInspect(stxn.Txn),
		Sig:  stxn.Sig,
		Msig: msigToInspect(stxn.Msig),
	}
}

func stxnFromInspect(sti inspectSignedTxn) transactions.SignedTxn {
	return transactions.SignedTxn{
		Txn:  txnFromInspect(sti.Txn),
		Sig:  sti.Sig,
		Msig: msigFromInspect(sti.Msig),
	}
}

func msigToInspect(msig crypto.MultisigSig) inspectMultisigSig {
	res := inspectMultisigSig{
		Version:   msig.Version,
		Threshold: msig.Threshold,
	}

	for _, subsig := range msig.Subsigs {
		res.Subsigs = append(res.Subsigs, inspectMultisigSubsig{
			Sig: subsig.Sig,
			Key: checksumAddress(subsig.Key),
		})
	}

	return res
}

func msigFromInspect(msi inspectMultisigSig) crypto.MultisigSig {
	res := crypto.MultisigSig{
		Version:   msi.Version,
		Threshold: msi.Threshold,
	}

	for _, subsig := range msi.Subsigs {
		res.Subsigs = append(res.Subsigs, crypto.MultisigSubsig{
			Sig: subsig.Sig,
			Key: crypto.PublicKey(subsig.Key),
		})
	}

	return res
}

func txnToInspect(txn transactions.Transaction) inspectTransaction {
	return inspectTransaction{
		Type: txn.Type,
		inspectTxnHeader: inspectTxnHeader{
			Sender:      checksumAddress(txn.Sender),
			Fee:         txn.Fee,
			FirstValid:  txn.FirstValid,
			LastValid:   txn.LastValid,
			Note:        txn.Note,
			GenesisID:   txn.GenesisID,
			GenesisHash: txn.GenesisHash,
		},
		KeyregTxnFields: txn.KeyregTxnFields,
		inspectPaymentTxnFields: inspectPaymentTxnFields{
			Receiver:         checksumAddress(txn.Receiver),
			Amount:           txn.Amount,
			CloseRemainderTo: checksumAddress(txn.CloseRemainderTo),
		},
	}
}

func txnFromInspect(txi inspectTransaction) transactions.Transaction {
	return transactions.Transaction{
		Type: txi.Type,
		Header: transactions.Header{
			Sender:      basics.Address(txi.Sender),
			Fee:         txi.Fee,
			FirstValid:  txi.FirstValid,
			LastValid:   txi.LastValid,
			Note:        txi.Note,
			GenesisID:   txi.GenesisID,
			GenesisHash: txi.GenesisHash,
		},
		KeyregTxnFields: txi.KeyregTxnFields,
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         basics.Address(txi.Receiver),
			Amount:           txi.Amount,
			CloseRemainderTo: basics.Address(txi.CloseRemainderTo),
		},
	}
}
