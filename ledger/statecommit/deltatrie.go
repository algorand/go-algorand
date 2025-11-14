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

package statecommit

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// stateChange represents any type of state change that can be encoded into a trie update.
// This interface abstracts over accounts, resources (assets/apps), and key-value pairs.
type stateChange interface {
	isDeleted() bool
	hasNewValue() bool
	encodeKey() []byte
	encodeValue() []byte
}

// Wrapper types to allow various delta types to implement the stateChange interface.
// Each wrapper provides methods for encoding one specific delta type.

//msgp:ignore accountUpdate
type accountUpdate ledgercore.BalanceRecord

func (u *accountUpdate) isDeleted() bool   { return u.AccountData.IsZero() }
func (u *accountUpdate) hasNewValue() bool { return !u.AccountData.IsZero() }
func (u *accountUpdate) encodeKey() []byte { return EncodeAccountKey(u.Addr) }
func (u *accountUpdate) encodeValue() []byte {
	// encode using codec tags on basics.AccountData
	var ad basics.AccountData
	ledgercore.AssignAccountData(&ad, u.AccountData)
	return protocol.Encode(&ad)
}

//msgp:ignore kvUpdate
type kvUpdate struct {
	key   *string
	delta *ledgercore.KvValueDelta
}

func (u *kvUpdate) isDeleted() bool     { return u.delta.Data == nil }
func (u *kvUpdate) hasNewValue() bool   { return u.delta.Data != nil }
func (u *kvUpdate) encodeKey() []byte   { return EncodeKvPairKey(*u.key) }
func (u *kvUpdate) encodeValue() []byte { return u.delta.Data } // XXX need to distinguish between nil and empty?

//msgp:ignore assetHoldingUpdate
type assetHoldingUpdate ledgercore.AssetResourceRecord

func (u *assetHoldingUpdate) isDeleted() bool     { return u.Holding.Deleted }
func (u *assetHoldingUpdate) hasNewValue() bool   { return u.Holding.Holding != nil }
func (u *assetHoldingUpdate) encodeKey() []byte   { return EncodeAssetHoldingKey(u.Addr, u.Aidx) }
func (u *assetHoldingUpdate) encodeValue() []byte { return protocol.Encode(u.Holding.Holding) }

//msgp:ignore assetParamsUpdate
type assetParamsUpdate ledgercore.AssetResourceRecord

func (u *assetParamsUpdate) isDeleted() bool     { return u.Params.Deleted }
func (u *assetParamsUpdate) hasNewValue() bool   { return u.Params.Params != nil }
func (u *assetParamsUpdate) encodeKey() []byte   { return EncodeAssetParamsKey(u.Addr, u.Aidx) }
func (u *assetParamsUpdate) encodeValue() []byte { return protocol.Encode(u.Params.Params) }

//msgp:ignore appLocalStateUpdate
type appLocalStateUpdate ledgercore.AppResourceRecord

func (u *appLocalStateUpdate) isDeleted() bool     { return u.State.Deleted }
func (u *appLocalStateUpdate) hasNewValue() bool   { return u.State.LocalState != nil }
func (u *appLocalStateUpdate) encodeKey() []byte   { return EncodeAppLocalStateKey(u.Addr, u.Aidx) }
func (u *appLocalStateUpdate) encodeValue() []byte { return protocol.Encode(u.State.LocalState) }

//msgp:ignore appParamsUpdate
type appParamsUpdate ledgercore.AppResourceRecord

func (u *appParamsUpdate) isDeleted() bool     { return u.Params.Deleted }
func (u *appParamsUpdate) hasNewValue() bool   { return u.Params.Params != nil }
func (u *appParamsUpdate) encodeKey() []byte   { return EncodeAppParamsKey(u.Addr, u.Aidx) }
func (u *appParamsUpdate) encodeValue() []byte { return protocol.Encode(u.Params.Params) }

// maybeCommitUpdate checks if an update has changes and adds it to the committer
func maybeCommitUpdate[T stateChange](update T, committer UpdateCommitter) error {
	if update.isDeleted() {
		return committer.Delete(update.encodeKey())
	}
	if update.hasNewValue() {
		return committer.Add(update.encodeKey(), update.encodeValue())
	}
	return nil
}

// StateDeltaCommitment computes a cryptographic commitment to all state changes in a StateDelta.
// This is the primary function for converting ledger state changes into a state commitment.
func StateDeltaCommitment(sd *ledgercore.StateDelta) (crypto.Sha512Digest, error) {
	return stateDeltaCommitmentWithCommitter(sd, newMerkleArrayCommitter())
}

// stateDeltaCommitmentWithCommitter computes a cryptographic commitment using the provided UpdateCommitter.
// This allows flexibility in the commitment scheme used.
func stateDeltaCommitmentWithCommitter(sd *ledgercore.StateDelta, committer UpdateCommitter) (crypto.Sha512Digest, error) {
	// Process base account data changes
	for i := range sd.Accts.Accts {
		if err := maybeCommitUpdate((*accountUpdate)(&sd.Accts.Accts[i]), committer); err != nil {
			return crypto.Sha512Digest{}, err
		}
	}

	// Process asset resources (holdings and params separately)
	for i := range sd.Accts.AssetResources {
		rec := &sd.Accts.AssetResources[i]
		if err := maybeCommitUpdate((*assetHoldingUpdate)(rec), committer); err != nil {
			return crypto.Sha512Digest{}, err
		}
		if err := maybeCommitUpdate((*assetParamsUpdate)(rec), committer); err != nil {
			return crypto.Sha512Digest{}, err
		}
	}

	// Process app resources (local state and params separately)
	for i := range sd.Accts.AppResources {
		rec := &sd.Accts.AppResources[i]
		if err := maybeCommitUpdate((*appLocalStateUpdate)(rec), committer); err != nil {
			return crypto.Sha512Digest{}, err
		}
		if err := maybeCommitUpdate((*appParamsUpdate)(rec), committer); err != nil {
			return crypto.Sha512Digest{}, err
		}
	}

	// Process KV modifications
	for key, kvDelta := range sd.KvMods {
		if err := maybeCommitUpdate(&kvUpdate{&key, &kvDelta}, committer); err != nil {
			return crypto.Sha512Digest{}, err
		}
	}

	return committer.Root()
}
