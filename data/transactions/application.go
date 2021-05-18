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

	"github.com/algorand/go-algorand/data/basics"
)

const (
	// encodedMaxApplicationArgs sets the allocation bound for the maximum
	// number of ApplicationArgs that a transaction decoded off of the wire
	// can contain. Its value is verified against consensus parameters in
	// TestEncodedAppTxnAllocationBounds
	encodedMaxApplicationArgs = 32

	// encodedMaxAccounts sets the allocation bound for the maximum number
	// of Accounts that a transaction decoded off of the wire can contain.
	// Its value is verified against consensus parameters in
	// TestEncodedAppTxnAllocationBounds
	encodedMaxAccounts = 32

	// encodedMaxForeignApps sets the allocation bound for the maximum
	// number of ForeignApps that a transaction decoded off of the wire can
	// contain. Its value is verified against consensus parameters in
	// TestEncodedAppTxnAllocationBounds
	encodedMaxForeignApps = 32

	// encodedMaxForeignAssets sets the allocation bound for the maximum
	// number of ForeignAssets that a transaction decoded off of the wire
	// can contain. Its value is verified against consensus parameters in
	// TestEncodedAppTxnAllocationBounds
	encodedMaxForeignAssets = 32
)

// OnCompletion is an enum representing some layer 1 side effect that an
// ApplicationCall transaction will have if it is included in a block.
//go:generate stringer -type=OnCompletion -output=application_string.go
type OnCompletion uint64

const (
	// NoOpOC indicates that an application transaction will simply call its
	// ApprovalProgram
	NoOpOC OnCompletion = 0

	// OptInOC indicates that an application transaction will allocate some
	// LocalState for the application in the sender's account
	OptInOC OnCompletion = 1

	// CloseOutOC indicates that an application transaction will deallocate
	// some LocalState for the application from the user's account
	CloseOutOC OnCompletion = 2

	// ClearStateOC is similar to CloseOutOC, but may never fail. This
	// allows users to reclaim their minimum balance from an application
	// they no longer wish to opt in to. When an ApplicationCall
	// transaction's OnCompletion is ClearStateOC, the ClearStateProgram
	// executes instead of the ApprovalProgram
	ClearStateOC OnCompletion = 3

	// UpdateApplicationOC indicates that an application transaction will
	// update the ApprovalProgram and ClearStateProgram for the application
	UpdateApplicationOC OnCompletion = 4

	// DeleteApplicationOC indicates that an application transaction will
	// delete the AppParams for the application from the creator's balance
	// record
	DeleteApplicationOC OnCompletion = 5
)

// ApplicationCallTxnFields captures the transaction fields used for all
// interactions with applications
type ApplicationCallTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// ApplicationID is 0 when creating an application, and nonzero when
	// calling an existing application.
	ApplicationID basics.AppIndex `codec:"apid"`

	// OnCompletion specifies an optional side-effect that this transaction
	// will have on the balance record of the sender or the application's
	// creator. See the documentation for the OnCompletion type for more
	// information on each possible value.
	OnCompletion OnCompletion `codec:"apan"`

	// ApplicationArgs are arguments accessible to the executing
	// ApprovalProgram or ClearStateProgram.
	ApplicationArgs [][]byte `codec:"apaa,allocbound=encodedMaxApplicationArgs"`

	// Accounts are accounts whose balance records are accessible by the
	// executing ApprovalProgram or ClearStateProgram. To access LocalState
	// for an account besides the sender, that account's address must be
	// listed here.
	Accounts []basics.Address `codec:"apat,allocbound=encodedMaxAccounts"`

	// ForeignApps are application IDs for applications besides this one
	// whose GlobalState may be read by the executing ApprovalProgram or
	// ClearStateProgram.
	ForeignApps []basics.AppIndex `codec:"apfa,allocbound=encodedMaxForeignApps"`

	// ForeignAssets are asset IDs for assets whose AssetParams may be read
	// by the executing ApprovalProgram or ClearStateProgram.
	ForeignAssets []basics.AssetIndex `codec:"apas,allocbound=encodedMaxForeignAssets"`

	// LocalStateSchema specifies the maximum number of each type that may
	// appear in the local key/value store of users who opt in to this
	// application. This field is only used during application creation
	// (when the ApplicationID field is 0),
	LocalStateSchema basics.StateSchema `codec:"apls"`

	// GlobalStateSchema specifies the maximum number of each type that may
	// appear in the global key/value store associated with this
	// application. This field is only used during application creation
	// (when the ApplicationID field is 0).
	GlobalStateSchema basics.StateSchema `codec:"apgs"`

	// ApprovalProgram is the stateful TEAL bytecode that executes on all
	// ApplicationCall transactions associated with this application,
	// except for those where OnCompletion is equal to ClearStateOC. If
	// this program fails, the transaction is rejected. This program may
	// read and write local and global state for this application.
	ApprovalProgram []byte `codec:"apap,allocbound=config.MaxAvailableAppProgramLen"`

	// ClearStateProgram is the stateful TEAL bytecode that executes on
	// ApplicationCall transactions associated with this application when
	// OnCompletion is equal to ClearStateOC. This program will not cause
	// the transaction to be rejected, even if it fails. This program may
	// read and write local and global state for this application.
	ClearStateProgram []byte `codec:"apsu,allocbound=config.MaxAvailableAppProgramLen"`

	// ExtraProgramPages specifies the additional app program len requested in pages.
	// A page is MaxAppProgramLen bytes. This field enables execution of app programs
	// larger than the default config, MaxAppProgramLen.
	ExtraProgramPages int `codec:"apep,omitempty"`

	// If you add any fields here, remember you MUST modify the Empty
	// method below!
}

// Empty indicates whether or not all the fields in the
// ApplicationCallTxnFields are zeroed out
func (ac *ApplicationCallTxnFields) Empty() bool {
	if ac.ApplicationID != 0 {
		return false
	}
	if ac.OnCompletion != 0 {
		return false
	}
	if ac.ApplicationArgs != nil {
		return false
	}
	if ac.Accounts != nil {
		return false
	}
	if ac.ForeignApps != nil {
		return false
	}
	if ac.ForeignAssets != nil {
		return false
	}
	if ac.LocalStateSchema != (basics.StateSchema{}) {
		return false
	}
	if ac.GlobalStateSchema != (basics.StateSchema{}) {
		return false
	}
	if ac.ApprovalProgram != nil {
		return false
	}
	if ac.ClearStateProgram != nil {
		return false
	}
	if ac.ExtraProgramPages != 0 {
		return false
	}
	return true
}

// AddressByIndex converts an integer index into an address associated with the
// transaction. Index 0 corresponds to the transaction sender, and an index > 0
// corresponds to an offset into txn.Accounts. Returns an error if the index is
// not valid.
func (ac *ApplicationCallTxnFields) AddressByIndex(accountIdx uint64, sender basics.Address) (basics.Address, error) {
	// Index 0 always corresponds to the sender
	if accountIdx == 0 {
		return sender, nil
	}

	// An index > 0 corresponds to an offset into txn.Accounts. Check to
	// make sure the index is valid.
	if accountIdx > uint64(len(ac.Accounts)) {
		err := fmt.Errorf("cannot load account[%d] of %d", accountIdx, len(ac.Accounts))
		return basics.Address{}, err
	}

	// accountIdx must be in [1, len(ac.Accounts)]
	return ac.Accounts[accountIdx-1], nil
}

// IndexByAddress converts an address into an integer offset into [txn.Sender,
// txn.Accounts[0], ...], returning the index at the first match. It returns
// an error if there is no such match.
func (ac *ApplicationCallTxnFields) IndexByAddress(target basics.Address, sender basics.Address) (uint64, error) {
	// Index 0 always corresponds to the sender
	if target == sender {
		return 0, nil
	}

	// Otherwise we index into ac.Accounts
	for idx, addr := range ac.Accounts {
		if target == addr {
			return uint64(idx) + 1, nil
		}
	}

	return 0, fmt.Errorf("could not find offset of address %s", target)
}
