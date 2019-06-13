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

	Sig  crypto.Signature         `codec:"sig"`
	Msig inspectMultisigSig       `codec:"msig"`
	Txn  transactions.Transaction `codec:"txn"`
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

	Key basics.Address   `codec:"pk"`
	Sig crypto.Signature `codec:"s"`
}

func inspectTxn(stxn transactions.SignedTxn) (sti inspectSignedTxn, err error) {
	sti = txnToInspect(stxn)
	if !reflect.DeepEqual(stxn, txnFromInspect(sti)) {
		err = fmt.Errorf("non-idempotent transformation to inspectSignedTxn (DeepEqual)")
	}
	if !reflect.DeepEqual(protocol.Encode(sti), protocol.Encode(stxn)) {
		err = fmt.Errorf("non-idempotent transformation to inspectSignedTxn (protocol.Encode)")
	}
	return
}

func txnToInspect(stxn transactions.SignedTxn) inspectSignedTxn {
	return inspectSignedTxn{
		Txn:  stxn.Txn,
		Sig:  stxn.Sig,
		Msig: msigToInspect(stxn.Msig),
	}
}

func txnFromInspect(sti inspectSignedTxn) transactions.SignedTxn {
	return transactions.SignedTxn{
		Txn:  sti.Txn,
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
			Key: basics.Address(subsig.Key),
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
