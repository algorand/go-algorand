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

package crypto

import (
	"errors"
)

// SecretKey is casted from SignatureSecrets
type SecretKey = SignatureSecrets

// MultisigSubsig is a struct that holds a pair of public key and signatures
// signatures may be empty
type MultisigSubsig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Key PublicKey `codec:"pk"` // all public keys that are possible signers for this address
	Sig Signature `codec:"s"`  // may be either empty or a signature
}

// MultisigSig is the structure that holds multiple Subsigs
type MultisigSig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Version   uint8            `codec:"v"`
	Threshold uint8            `codec:"thr"`
	Subsigs   []MultisigSubsig `codec:"subsig,allocbound=maxMultisig"`
}

// MultisigPreimageFromPKs makes an empty MultisigSig for a given preimage. It should be renamed.
// TODO separate preimage type from sig type
func MultisigPreimageFromPKs(version, threshold uint8, pks []PublicKey) MultisigSig {
	out := MultisigSig{Version: version, Threshold: threshold, Subsigs: make([]MultisigSubsig, len(pks))}
	for i := range pks {
		out.Subsigs[i].Key = pks[i]
	}
	return out
}

// Blank returns true iff the msig is empty. We need this instead of just
// comparing with == MultisigSig{}, because Subsigs is a slice.
func (msig MultisigSig) Blank() bool {
	if msig.Version != 0 {
		return false
	}
	if msig.Threshold != 0 {
		return false
	}
	if msig.Subsigs != nil {
		return false
	}
	return true
}

// Preimage returns the version, threshold, and list of all public keys in a (partial) multisig address
func (msig MultisigSig) Preimage() (version, threshold uint8, pks []PublicKey) {
	pks = make([]PublicKey, len(msig.Subsigs))
	for i, subsig := range msig.Subsigs {
		pks[i] = subsig.Key
	}
	return msig.Version, msig.Threshold, pks
}

const multiSigString = "MultisigAddr"
const maxMultisig = 255

// MultisigAddrGen identifes the exact group, version,
// and devices (Public keys) that it requires to sign
// Hash("MultisigAddr" || version uint8 || threshold uint8 || PK1 || PK2 || ...)
func MultisigAddrGen(version, threshold uint8, pk []PublicKey) (addr Digest, err error) {
	if version != 1 {
		err = errUnknownVersion
		return
	}

	if threshold == 0 || len(pk) == 0 || int(threshold) > len(pk) {
		err = errors.New(errorinvalidthreshold)
		return
	}

	buffer := append([]byte(multiSigString), byte(version), byte(threshold))
	for _, pki := range pk {
		buffer = append(buffer, pki[:]...)
	}
	return Hash(buffer), nil
}

// MultisigAddrGenWithSubsigs is similiar to MultisigAddrGen
// except the input is []Subsig rather than []PublicKey
func MultisigAddrGenWithSubsigs(version uint8, threshold uint8,
	subsigs []MultisigSubsig) (addr Digest, err error) {

	if version != 1 {
		err = errUnknownVersion
		return
	}

	if threshold == 0 || len(subsigs) == 0 || int(threshold) > len(subsigs) {
		err = errors.New(errorinvalidthreshold)
		return
	}

	buffer := append([]byte(multiSigString), byte(version), byte(threshold))
	for _, subsigsi := range subsigs {
		buffer = append(buffer, subsigsi.Key[:]...)
	}
	return Hash(buffer), nil
}

// MultisigSign is for each device individually signs the digest
func MultisigSign(msg Hashable, addr Digest, version, threshold uint8, pk []PublicKey, sk SecretKey) (sig MultisigSig, err error) {
	if version != 1 {
		err = errUnknownVersion
		return
	}

	// check the address matches the keys
	addrnew, err := MultisigAddrGen(version, threshold, pk)
	if err != nil {
		return
	}

	if addr != addrnew {
		err = errors.New(errorinvalidaddress)
		return
	}

	// setup parameters
	sig.Version = version
	sig.Threshold = threshold
	sig.Subsigs = make([]MultisigSubsig, len(pk))

	// check if sk.pk exist in the pk list
	keyexist := len(pk)
	for i := 0; i < len(pk); i++ {
		if sk.SignatureVerifier == pk[i] {
			keyexist = i
		}
	}
	if keyexist == len(pk) {
		err = errors.New(errorkeynotexist)
		return
	}

	// form the multisig
	for i := 0; i < len(pk); i++ {
		sig.Subsigs[i].Key = pk[i]
		if sk.SignatureVerifier == pk[i] {
			sig.Subsigs[i].Sig = sk.Sign(msg)
		}
	}
	return
}

// MultisigAssemble assembles multiple MultisigSig
func MultisigAssemble(unisig []MultisigSig) (msig MultisigSig, err error) {

	if len(unisig) < 2 {
		err = errors.New("invalid number of signatures to assemble")
		return
	}

	// check if all unisig match
	for i := 1; i < len(unisig); i++ {
		if unisig[0].Threshold != unisig[i].Threshold {
			err = errors.New(errorinvalidthreshold)
			return
		}
		if unisig[0].Version != unisig[i].Version {
			err = errors.New(errorinvalidversion)
			return
		}
		if len(unisig[0].Subsigs) != len(unisig[i].Subsigs) {
			err = errors.New(errorinvalidnumberofsignature)
			return
		}
		for j := 0; j < len(unisig[0].Subsigs); j++ {
			if unisig[0].Subsigs[j].Key != unisig[i].Subsigs[j].Key {
				err = errors.New(errorkeysnotmatch)
				return
			}
		}
	}

	// make the assembled signature

	msig.Version = unisig[0].Version
	msig.Threshold = unisig[0].Threshold
	msig.Subsigs = make([]MultisigSubsig, len(unisig[0].Subsigs))

	for i := 0; i < len(unisig[0].Subsigs); i++ {
		msig.Subsigs[i].Key = unisig[0].Subsigs[i].Key
	}
	for i := 0; i < len(unisig); i++ {
		for j := 0; j < len(unisig[0].Subsigs); j++ {
			if (unisig[i].Subsigs[j].Sig != Signature{}) {
				msig.Subsigs[j].Sig = unisig[i].Subsigs[j].Sig
			}
		}
	}
	return
}

// MultisigVerify verifies an assembled MultisigSig
func MultisigVerify(msg Hashable, addr Digest, sig MultisigSig) (verified bool, err error) {

	verified = false
	// short circuit: if msig doesn't have subsigs or if Subsigs are empty
	// then terminate (the upper layer should now verify the unisig)
	if (len(sig.Subsigs) == 0 || sig.Subsigs[0] == MultisigSubsig{}) {
		return
	}

	// check the address is correct
	addrnew, err := MultisigAddrGenWithSubsigs(sig.Version, sig.Threshold, sig.Subsigs)
	if err != nil {
		return
	}
	if addr != addrnew {
		err = errors.New(errorinvalidaddress)
		return
	}

	// check that we don't have too many multisig subsigs
	if len(sig.Subsigs) > maxMultisig {
		err = errors.New(errorinvalidnumberofsignature)
		return
	}

	// check that we don't have too few multisig subsigs
	if len(sig.Subsigs) < int(sig.Threshold) {
		err = errors.New(errorinvalidnumberofsignature)
		return
	}

	// checks the number of non-blank signatures is no less than threshold
	var counter uint8
	for _, subsigi := range sig.Subsigs {
		if (subsigi.Sig != Signature{}) {
			counter++
		}
	}
	if counter < sig.Threshold {
		err = errors.New(errorinvalidnumberofsignature)
		return
	}

	// checks individual signature verifies
	var verifiedCount int
	for _, subsigi := range sig.Subsigs {
		if (subsigi.Sig != Signature{}) {
			if !subsigi.Key.Verify(msg, subsigi.Sig) {
				err = errors.New(errorsubsigverification)
				return
			}
			verifiedCount++
		}
	}

	// sanity check. if we get here then every non-blank subsig should have
	// been verified successfully, and we should have had enough of them
	if verifiedCount < int(sig.Threshold) {
		err = errors.New(errorinvalidnumberofsignature)
		return
	}

	verified = true
	return
}

// MultisigAdd adds unisig to an existing msig
func MultisigAdd(unisig []MultisigSig, msig *MultisigSig) (err error) {
	if len(unisig) < 1 || msig == nil {
		err = errors.New("invalid number of signatures to add")
		return
	}

	// check if all unisig match
	for i := 0; i < len(unisig); i++ {
		if msig.Threshold != unisig[i].Threshold {
			err = errors.New(errorinvalidthreshold)
			return
		}

		if msig.Version != unisig[i].Version {
			err = errors.New(errorinvalidversion)
			return
		}

		if len(msig.Subsigs) != len(unisig[i].Subsigs) {
			err = errors.New(errorkeysnotmatch)
			return
		}
		for j := 0; j < len(unisig[0].Subsigs); j++ {
			if msig.Subsigs[j].Key != unisig[i].Subsigs[j].Key {
				err = errors.New(errorkeysnotmatch)
				return
			}
		}
	}
	// update the msig
	for i := 0; i < len(unisig); i++ {
		for j := 0; j < len(msig.Subsigs); j++ {
			if (unisig[i].Subsigs[j].Sig != Signature{}) {
				if (msig.Subsigs[j].Sig == Signature{}) {
					// add the siganture
					msig.Subsigs[j].Sig = unisig[i].Subsigs[j].Sig
				} else if msig.Subsigs[j].Sig != unisig[i].Subsigs[j].Sig {
					// invalid duplicates
					err = errors.New(errorinvalidduplicates)
					return
				} else {
					// valid duplicates
				}
			}
		}
	}
	return
}

// MultisigMerge merges two Multisigs msig1 and msig2 into msigt
func MultisigMerge(msig1 MultisigSig, msig2 MultisigSig) (msigt MultisigSig, err error) {

	// check if all parameters match
	if msig1.Threshold != msig2.Threshold ||
		msig1.Version != msig2.Version ||
		len(msig1.Subsigs) != len(msig2.Subsigs) {
		err = errors.New(errorinvalidthreshold)
		return
	}
	for i := 0; i < len(msig1.Subsigs); i++ {
		if msig1.Subsigs[i].Key != msig2.Subsigs[i].Key {
			err = errors.New(errorkeysnotmatch)
			return
		}
	}
	// update msigt
	msigt.Threshold = msig1.Threshold
	msigt.Version = msig1.Version
	msigt.Subsigs = make([]MultisigSubsig, len(msig1.Subsigs))
	for i := 0; i < len(msigt.Subsigs); i++ {
		msigt.Subsigs[i].Key = msig1.Subsigs[i].Key
		if (msig1.Subsigs[i].Sig == Signature{}) {
			if (msig2.Subsigs[i].Sig != Signature{}) {
				// update signature with msig2's signature
				msigt.Subsigs[i].Sig = msig2.Subsigs[i].Sig
			}
		} else if (msig2.Subsigs[i].Sig == Signature{} || // msig2's sig is empty
			msig2.Subsigs[i].Sig == msig1.Subsigs[i].Sig) { // valid duplicates
			// update signature with msig1's signature
			msigt.Subsigs[i].Sig = msig1.Subsigs[i].Sig
		} else {
			// invalid duplicates
			err = errors.New(errorinvalidduplicates)
			msigt = MultisigSig{}
			return
		}
	}
	return

}

// Equal compares two MultisigSig structs for equality
func (msig MultisigSig) Equal(other MultisigSig) bool {
	if msig.Version != other.Version {
		return false
	}

	if msig.Threshold != other.Threshold {
		return false
	}

	if len(msig.Subsigs) != len(other.Subsigs) {
		return false
	}

	for i := 0; i < len(msig.Subsigs); i++ {
		if msig.Subsigs[i] != other.Subsigs[i] {
			return false
		}
	}

	return true
}
