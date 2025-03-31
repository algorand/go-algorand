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
	"slices"

	"github.com/algorand/go-algorand/config"
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

	// encodedMaxBoxes sets the allocation bound for the maximum
	// number of Boxes that a transaction decoded off of the wire
	// can contain. Its value is verified against consensus parameters in
	// TestEncodedAppTxnAllocationBounds
	encodedMaxBoxes = 32
)

// OnCompletion is an enum representing some layer 1 side effect that an
// ApplicationCall transaction will have if it is included in a block.
//
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
	ApplicationArgs [][]byte `codec:"apaa,allocbound=encodedMaxApplicationArgs,maxtotalbytes=config.MaxAppTotalArgLen"`

	// Accounts are accounts whose balance records are accessible
	// by the executing ApprovalProgram or ClearStateProgram. To
	// access LocalState or an ASA balance for an account besides
	// the sender, that account's address must be listed here (and
	// since v4, the ForeignApp or ForeignAsset must also include
	// the app or asset id).
	Accounts []basics.Address `codec:"apat,allocbound=encodedMaxAccounts"`

	// ForeignApps are application IDs for applications besides
	// this one whose GlobalState (or Local, since v4) may be read
	// by the executing ApprovalProgram or ClearStateProgram.
	ForeignApps []basics.AppIndex `codec:"apfa,allocbound=encodedMaxForeignApps"`

	// Boxes are the boxes that can be accessed by this transaction (and others
	// in the same group). The Index in the BoxRef is the slot of ForeignApps
	// that the name is associated with (shifted by 1, so 0 indicates "current
	// app")
	Boxes []BoxRef `codec:"apbx,allocbound=encodedMaxBoxes"`

	// ForeignAssets are asset IDs for assets whose AssetParams
	// (and since v4, Holdings) may be read by the executing
	// ApprovalProgram or ClearStateProgram.
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
	ExtraProgramPages uint32 `codec:"apep,omitempty"`

	// If you add any fields here, remember you MUST modify the Empty
	// method below!
}

// BoxRef names a box by the slot
type BoxRef struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Index uint64 `codec:"i"`
	Name  []byte `codec:"n,allocbound=config.MaxBytesKeyValueLen"`
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
	if ac.Boxes != nil {
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

// wellFormed performs some stateless checks on the ApplicationCall transaction
func (ac ApplicationCallTxnFields) wellFormed(proto config.ConsensusParams) error {

	// Ensure requested action is valid
	switch ac.OnCompletion {
	case NoOpOC, OptInOC, CloseOutOC, ClearStateOC, UpdateApplicationOC, DeleteApplicationOC:
		/* ok */
	default:
		return fmt.Errorf("invalid application OnCompletion")
	}

	// Programs may only be set for creation or update
	if ac.ApplicationID != 0 && ac.OnCompletion != UpdateApplicationOC {
		if len(ac.ApprovalProgram) != 0 || len(ac.ClearStateProgram) != 0 {
			return fmt.Errorf("programs may only be specified during application creation or update")
		}
	} else {
		// This will check version matching, but not downgrading. That
		// depends on chain state (so we pass an empty AppParams)
		err := CheckContractVersions(ac.ApprovalProgram, ac.ClearStateProgram, basics.AppParams{}, &proto)
		if err != nil {
			return err
		}
	}

	effectiveEPP := ac.ExtraProgramPages
	// Schemas and ExtraProgramPages may only be set during application creation
	if ac.ApplicationID != 0 {
		if ac.LocalStateSchema != (basics.StateSchema{}) ||
			ac.GlobalStateSchema != (basics.StateSchema{}) {
			return fmt.Errorf("local and global state schemas are immutable")
		}
		if ac.ExtraProgramPages != 0 {
			return fmt.Errorf("tx.ExtraProgramPages is immutable")
		}

		if proto.EnableExtraPagesOnAppUpdate {
			effectiveEPP = uint32(proto.MaxExtraAppProgramPages)
		}

	}

	// Limit total number of arguments
	if len(ac.ApplicationArgs) > proto.MaxAppArgs {
		return fmt.Errorf("too many application args, max %d", proto.MaxAppArgs)
	}

	// Sum up argument lengths
	var argSum uint64
	for _, arg := range ac.ApplicationArgs {
		argSum = basics.AddSaturate(argSum, uint64(len(arg)))
	}

	// Limit total length of all arguments
	if argSum > uint64(proto.MaxAppTotalArgLen) {
		return fmt.Errorf("application args total length too long, max len %d bytes", proto.MaxAppTotalArgLen)
	}

	// Limit number of accounts referred to in a single ApplicationCall
	if len(ac.Accounts) > proto.MaxAppTxnAccounts {
		return fmt.Errorf("tx.Accounts too long, max number of accounts is %d", proto.MaxAppTxnAccounts)
	}

	// Limit number of other app global states referred to
	if len(ac.ForeignApps) > proto.MaxAppTxnForeignApps {
		return fmt.Errorf("tx.ForeignApps too long, max number of foreign apps is %d", proto.MaxAppTxnForeignApps)
	}

	if len(ac.ForeignAssets) > proto.MaxAppTxnForeignAssets {
		return fmt.Errorf("tx.ForeignAssets too long, max number of foreign assets is %d", proto.MaxAppTxnForeignAssets)
	}

	if len(ac.Boxes) > proto.MaxAppBoxReferences {
		return fmt.Errorf("tx.Boxes too long, max number of box references is %d", proto.MaxAppBoxReferences)
	}

	// Limit the sum of all types of references that bring in account records
	if len(ac.Accounts)+len(ac.ForeignApps)+len(ac.ForeignAssets)+len(ac.Boxes) > proto.MaxAppTotalTxnReferences {
		return fmt.Errorf("tx references exceed MaxAppTotalTxnReferences = %d", proto.MaxAppTotalTxnReferences)
	}

	if ac.ExtraProgramPages > uint32(proto.MaxExtraAppProgramPages) {
		return fmt.Errorf("tx.ExtraProgramPages exceeds MaxExtraAppProgramPages = %d", proto.MaxExtraAppProgramPages)
	}

	lap := len(ac.ApprovalProgram)
	lcs := len(ac.ClearStateProgram)
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

	for i, br := range ac.Boxes {
		// recall 0 is the current app so indexes are shifted, thus test is for greater than, not gte.
		if br.Index > uint64(len(ac.ForeignApps)) {
			return fmt.Errorf("tx.Boxes[%d].Index is %d. Exceeds len(tx.ForeignApps)", i, br.Index)
		}
		if proto.EnableBoxRefNameError && len(br.Name) > proto.MaxAppKeyLen {
			return fmt.Errorf("tx.Boxes[%d].Name too long, max len %d bytes", i, proto.MaxAppKeyLen)
		}
	}

	if ac.LocalStateSchema.NumEntries() > proto.MaxLocalSchemaEntries {
		return fmt.Errorf("tx.LocalStateSchema too large, max number of keys is %d", proto.MaxLocalSchemaEntries)
	}

	if ac.GlobalStateSchema.NumEntries() > proto.MaxGlobalSchemaEntries {
		return fmt.Errorf("tx.GlobalStateSchema too large, max number of keys is %d", proto.MaxGlobalSchemaEntries)
	}

	return nil
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
		return basics.Address{}, fmt.Errorf("invalid Account reference %d", accountIdx)
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
	if idx := slices.Index(ac.Accounts, target); idx != -1 {
		return uint64(idx) + 1, nil
	}

	return 0, fmt.Errorf("invalid Account reference %s", target)
}
