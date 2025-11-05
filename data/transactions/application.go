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
	"errors"
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

	// encodedMaxAccess sets the allocation bound for the maximum number of
	// references in Access that a transaction decoded off of the wire can
	// contain. Its value is verified against consensus parameters in
	// TestEncodedAppTxnAllocationBounds
	encodedMaxAccess = 64
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
	ApplicationArgs [][]byte `codec:"apaa,allocbound=encodedMaxApplicationArgs,maxtotalbytes=bounds.MaxAppTotalArgLen"`

	// Accounts are accounts whose balance records are accessible
	// by the executing ApprovalProgram or ClearStateProgram. To
	// access LocalState or an ASA balance for an account besides
	// the sender, that account's address must be listed here (and
	// since v4, the ForeignApp or ForeignAsset must also include
	// the app or asset id).
	Accounts []basics.Address `codec:"apat,allocbound=encodedMaxAccounts"`

	// ForeignAssets are asset IDs for assets whose AssetParams
	// (and since v4, Holdings) may be read by the executing
	// ApprovalProgram or ClearStateProgram.
	ForeignAssets []basics.AssetIndex `codec:"apas,allocbound=encodedMaxForeignAssets"`

	// ForeignApps are application IDs for applications besides
	// this one whose GlobalState (or Local, since v4) may be read
	// by the executing ApprovalProgram or ClearStateProgram.
	ForeignApps []basics.AppIndex `codec:"apfa,allocbound=encodedMaxForeignApps"`

	// Access unifies `Accounts`, `ForeignApps`, `ForeignAssets`, and `Boxes`
	// under a single list. It removes all implicitly available resources, so
	// "cross-product" resources (holdings and locals) must be explicitly
	// listed, as well as app accounts, even the app account of the called app!
	// Transactions using Access may not use the other lists.
	Access []ResourceRef `codec:"al,allocbound=encodedMaxAccess"`

	// Boxes are the boxes that can be accessed by this transaction (and others
	// in the same group). The Index in the BoxRef is the slot of ForeignApps
	// that the name is associated with (shifted by 1. 0 indicates "current
	// app")
	Boxes []BoxRef `codec:"apbx,allocbound=encodedMaxBoxes"`

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
	ApprovalProgram []byte `codec:"apap,allocbound=bounds.MaxAvailableAppProgramLen"`

	// ClearStateProgram is the stateful TEAL bytecode that executes on
	// ApplicationCall transactions associated with this application when
	// OnCompletion is equal to ClearStateOC. This program will not cause
	// the transaction to be rejected, even if it fails. This program may
	// read and write local and global state for this application.
	ClearStateProgram []byte `codec:"apsu,allocbound=bounds.MaxAvailableAppProgramLen"`

	// ExtraProgramPages specifies the additional app program len requested in pages.
	// A page is MaxAppProgramLen bytes. This field enables execution of app programs
	// larger than the default config, MaxAppProgramLen.
	ExtraProgramPages uint32 `codec:"apep"`

	// RejectVersion is the lowest application version for which this
	// transaction should immediately fail. 0 indicates that no version check should be performed.
	RejectVersion uint64 `codec:"aprv"`

	// If you add any fields here, remember you MUST modify the Empty
	// method below!
}

// ResourceRef names a single resource
type ResourceRef struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Only one of these may be set
	Address basics.Address    `codec:"d"`
	Asset   basics.AssetIndex `codec:"s"`
	App     basics.AppIndex   `codec:"p"`
	Holding HoldingRef        `codec:"h"`
	Locals  LocalsRef         `codec:"l"`
	Box     BoxRef            `codec:"b"`
}

// Empty ResourceRefs are allowed, as they ask for a box quota bump.
func (rr ResourceRef) Empty() bool {
	return rr.Address.IsZero() && rr.Asset == 0 && rr.App == 0 &&
		rr.Holding.Empty() && rr.Locals.Empty() && rr.Box.Empty()
}

// wellFormed checks that a ResourceRef is a proper member of `access. `rr` is
// either empty a single kind of resource. Any internal indices point to proper
// locations inside `access`.
func (rr ResourceRef) wellFormed(access []ResourceRef, proto config.ConsensusParams) error {
	// Count the number of non-empty fields
	count := 0
	// The "basic" resources are inherently wellFormed
	if !rr.Address.IsZero() {
		count++
	}
	if rr.Asset != 0 {
		count++
	}
	if rr.App != 0 {
		count++
	}
	// The references that have indices need to be checked
	if !rr.Holding.Empty() {
		if _, _, err := rr.Holding.Resolve(access, basics.Address{}); err != nil {
			return err
		}
		count++
	}
	if !rr.Locals.Empty() {
		if _, _, err := rr.Locals.Resolve(access, basics.Address{}); err != nil {
			return err
		}
		count++
	}
	if !rr.Box.Empty() {
		if proto.EnableBoxRefNameError && len(rr.Box.Name) > proto.MaxAppKeyLen {
			return fmt.Errorf("tx.Access box Name too long, max len %d bytes", proto.MaxAppKeyLen)
		}
		if _, _, err := rr.Box.Resolve(access); err != nil {
			return err
		}
		count++
	}
	switch count {
	case 0:
		if !rr.Empty() { // If it's not one of those, it has to be empty
			return fmt.Errorf("tx.Access with unknown content")
		}
		return nil
	case 1:
		return nil
	default:
		return fmt.Errorf("tx.Access element has fields from multiple types")
	}
}

// HoldingRef names a holding by referring to an Address and Asset that appear
// earlier in the Access list (0 is special cased)
type HoldingRef struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	Address uint64   `codec:"d"` // 0=Sender,n-1=index into the Access list, which must be an Address
	Asset   uint64   `codec:"s"` // n-1=index into the Access list, which must be an Asset
}

// Empty does the obvious. An empty HoldingRef has no meaning, since we define
// hr.Asset to be a 1-based index for consistency with LocalRef (which does it
// because 0 means "this app")
func (hr HoldingRef) Empty() bool {
	return hr == HoldingRef{}
}

// Resolve looks up the referenced address and asset in the access list
func (hr HoldingRef) Resolve(access []ResourceRef, sender basics.Address) (basics.Address, basics.AssetIndex, error) {
	address := sender // Returned when hr.Address == 0
	if hr.Address != 0 {
		if hr.Address > uint64(len(access)) { // recall that Access is 1-based
			return basics.Address{}, 0, fmt.Errorf("holding Address reference %d outside tx.Access", hr.Address)
		}
		address = access[hr.Address-1].Address
		if address.IsZero() {
			return basics.Address{}, 0, fmt.Errorf("holding Address reference %d is not an Address", hr.Address)
		}
	}
	if hr.Asset == 0 || hr.Asset > uint64(len(access)) { // 1-based
		return basics.Address{}, 0, fmt.Errorf("holding Asset reference %d outside tx.Access", hr.Asset)
	}
	asset := access[hr.Asset-1].Asset
	if asset == 0 {
		return basics.Address{}, 0, fmt.Errorf("holding Asset reference %d is not an Asset", hr.Asset)
	}
	return address, asset, nil
}

// LocalsRef names a local state by referring to an Address and App that appear
// earlier in the Access list (0 is special cased)
type LocalsRef struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	Address uint64   `codec:"d"` // 0=Sender,n-1=index into the Access list, which must be an Address
	App     uint64   `codec:"p"` // 0=ApplicationID,n-1=index into the Access list, which must be an App
}

// Empty does the obvious. An empty LocalsRef makes no sense, because it would
// mean "give access to the sender's locals for this app", which is implicit.
func (lr LocalsRef) Empty() bool {
	return lr == LocalsRef{}
}

// Resolve looks up the referenced address and app in the access list. 0 is
// returned if the App index is 0, meaning "current app".
func (lr LocalsRef) Resolve(access []ResourceRef, sender basics.Address) (basics.Address, basics.AppIndex, error) {
	address := sender // Returned when lr.Address == 0
	if lr.Address != 0 {
		if lr.Address > uint64(len(access)) { // recall that Access is 1-based
			return basics.Address{}, 0, fmt.Errorf("locals Address reference %d outside tx.Access", lr.Address)
		}
		address = access[lr.Address-1].Address
		if address.IsZero() {
			return basics.Address{}, 0, fmt.Errorf("locals Address reference %d is not an Address", lr.Address)
		}
	}
	if lr.App == 0 || lr.App > uint64(len(access)) { // 1-based
		return basics.Address{}, 0, fmt.Errorf("locals App reference %d outside tx.Access", lr.App)
	}
	app := access[lr.App-1].App
	if app == 0 {
		return basics.Address{}, 0, fmt.Errorf("locals App reference %d is not an App", lr.App)
	}
	return address, app, nil
}

// BoxRef names a box by the slot. In the Boxes field, `i` is an index into
// ForeignApps. As an entry in Access, `i` is a index into Access itself.
type BoxRef struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	Index   uint64   `codec:"i"`
	Name    []byte   `codec:"n,allocbound=bounds.MaxBytesKeyValueLen"`
}

// Empty does the obvious. But the meaning is not obvious. An empty BoxRef just
// adds to the read/write quota of the transaction. In tx.Access, _any_ empty
// ResourceRef bumps the read/write quota. (We cannot distinguish the type when
// all are empty.)
func (br BoxRef) Empty() bool {
	return br.Index == 0 && br.Name == nil
}

// Resolve looks up the referenced app and returns it with the name. 0 is
// returned if the App index is 0, meaning "current app".
func (br BoxRef) Resolve(access []ResourceRef) (basics.AppIndex, string, error) {
	switch {
	case br.Index == 0:
		return 0, string(br.Name), nil
	case br.Index <= uint64(len(access)): // 1-based
		rr := access[br.Index-1]
		if app := rr.App; app != 0 {
			return app, string(br.Name), nil
		}
		return 0, "", fmt.Errorf("box Index reference %d is not an App", br.Index)
	default:
		return 0, "", fmt.Errorf("box Index %d outside tx.Access", br.Index)
	}
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
	if ac.Access != nil {
		return false
	}
	if !ac.LocalStateSchema.Empty() {
		return false
	}
	if !ac.GlobalStateSchema.Empty() {
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
	if ac.RejectVersion != 0 {
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
		return fmt.Errorf("invalid application OnCompletion (%d)", ac.OnCompletion)
	}

	if !proto.EnableAppVersioning && ac.RejectVersion > 0 {
		return fmt.Errorf("tx.RejectVersion is not supported")
	}

	if ac.RejectVersion > 0 && ac.ApplicationID == 0 {
		return fmt.Errorf("tx.RejectVersion cannot be set during creation")
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

	if ac.ExtraProgramPages > uint32(proto.MaxExtraAppProgramPages) {
		return fmt.Errorf("tx.ExtraProgramPages exceeds MaxExtraAppProgramPages = %d", proto.MaxExtraAppProgramPages)
	}

	effectiveEPP := ac.ExtraProgramPages
	// Schemas and ExtraProgramPages may only be set during application creation
	// and explicit attempts to change size during updates.
	if ac.ApplicationID != 0 && !(proto.AppSizeUpdates && ac.UpdatingSizes()) {
		if !ac.GlobalStateSchema.Empty() {
			return fmt.Errorf("inappropriate non-zero tx.GlobalStateSchema (%v)",
				ac.GlobalStateSchema)
		}
		if !ac.LocalStateSchema.Empty() {
			return fmt.Errorf("inappropriate non-zero tx.LocalStateSchema (%v)",
				ac.LocalStateSchema)
		}
		if ac.ExtraProgramPages != 0 {
			return fmt.Errorf("inappropriate non-zero tx.ExtraProgramPages (%d)",
				ac.ExtraProgramPages)
		}
		// allow maximimum size programs for now, since we have not checked the
		// app params to know the actual epp.
		effectiveEPP = uint32(proto.MaxExtraAppProgramPages)
	}

	if err := ac.WellSizedPrograms(effectiveEPP, proto); err != nil {
		return err
	}

	// Limit total number of arguments
	if len(ac.ApplicationArgs) > proto.MaxAppArgs {
		return fmt.Errorf("tx.ApplicationArgs has too many arguments. %d > %d",
			len(ac.ApplicationArgs), proto.MaxAppArgs)
	}

	// Sum up argument lengths
	var argSum uint64
	for _, arg := range ac.ApplicationArgs {
		argSum = basics.AddSaturate(argSum, uint64(len(arg)))
	}

	// Limit total length of all arguments
	if argSum > uint64(proto.MaxAppTotalArgLen) {
		return fmt.Errorf("tx.ApplicationArgs total length is too long. %d > %d",
			argSum, proto.MaxAppTotalArgLen)
	}

	if len(ac.Access) > 0 {
		if len(ac.Access) > proto.MaxAppAccess {
			return fmt.Errorf("tx.Access too long, max number of references is %d", proto.MaxAppAccess)
		}
		// When ac.Access is used, no other references are allowed
		if len(ac.Accounts) > 0 {
			return errors.New("tx.Accounts can't be used when tx.Access is used")
		}
		if len(ac.ForeignApps) > 0 {
			return errors.New("tx.ForeignApps can't be used when tx.Access is used")
		}
		if len(ac.ForeignAssets) > 0 {
			return errors.New("tx.ForeignAssets can't be used when tx.Access is used")
		}
		if len(ac.Boxes) > 0 {
			return errors.New("tx.Boxes can't be used when tx.Access is used")
		}

		for _, rr := range ac.Access {
			if err := rr.wellFormed(ac.Access, proto); err != nil {
				return err
			}
		}
	} else {
		if len(ac.Accounts) > proto.MaxAppTxnAccounts {
			return fmt.Errorf("tx.Accounts too long, max number of accounts is %d", proto.MaxAppTxnAccounts)
		}
		if len(ac.ForeignApps) > proto.MaxAppTxnForeignApps {
			return fmt.Errorf("tx.ForeignApps too long, max number of foreign apps is %d", proto.MaxAppTxnForeignApps)
		}
		if len(ac.ForeignAssets) > proto.MaxAppTxnForeignAssets {
			return fmt.Errorf("tx.ForeignAssets too long, max number of foreign assets is %d", proto.MaxAppTxnForeignAssets)
		}
		if len(ac.Boxes) > proto.MaxAppBoxReferences {
			return fmt.Errorf("tx.Boxes too long, max number of box references is %d", proto.MaxAppBoxReferences)
		}

		// Limit the sum of all types of references that bring in resource records
		if len(ac.Accounts)+len(ac.ForeignApps)+len(ac.ForeignAssets)+len(ac.Boxes) > proto.MaxAppTotalTxnReferences {
			return fmt.Errorf("tx references exceed MaxAppTotalTxnReferences = %d", proto.MaxAppTotalTxnReferences)
		}
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
		return fmt.Errorf("tx.LocalStateSchema is too large. %d > %d",
			ac.LocalStateSchema.NumEntries(), proto.MaxLocalSchemaEntries)
	}

	if ac.GlobalStateSchema.NumEntries() > proto.MaxGlobalSchemaEntries {
		return fmt.Errorf("tx.GlobalStateSchema is too large. %d > %d",
			ac.GlobalStateSchema.NumEntries(), proto.MaxGlobalSchemaEntries)
	}

	return nil
}

// UpdatingSizes returns true if this is an application update transaction that has non-zero sizing fields.
func (ac ApplicationCallTxnFields) UpdatingSizes() bool {
	return ac.OnCompletion == UpdateApplicationOC &&
		(ac.ExtraProgramPages != 0 || !ac.GlobalStateSchema.Empty())
}

// WellSizedPrograms checks the sizes of the programs in ac, based on the
// parameters of proto and returns an error if they are too big.
func (ac ApplicationCallTxnFields) WellSizedPrograms(extraPages uint32, proto config.ConsensusParams) error {
	lap := len(ac.ApprovalProgram)
	lcs := len(ac.ClearStateProgram)
	pages := int(1 + extraPages)
	if lap > pages*proto.MaxAppProgramLen {
		return fmt.Errorf("approval program too long. max len %d bytes", pages*proto.MaxAppProgramLen)
	}
	if lcs > pages*proto.MaxAppProgramLen {
		return fmt.Errorf("clear state program too long. max len %d bytes", pages*proto.MaxAppProgramLen)
	}
	if lap+lcs > pages*proto.MaxAppTotalProgramLen {
		return fmt.Errorf("app programs too long. max total len %d bytes", pages*proto.MaxAppTotalProgramLen)
	}
	return nil
}

// AddressByIndex converts an integer index into an address associated with the
// transaction. Index 0 corresponds to the transaction sender, and an index > 0
// corresponds to an offset into txn.Accounts or txn.Access. Returns an error if the index is
// not valid.
func (ac *ApplicationCallTxnFields) AddressByIndex(accountIdx uint64, sender basics.Address) (basics.Address, error) {
	// Index 0 always corresponds to the sender
	if accountIdx == 0 {
		return sender, nil
	}

	if ac.Access != nil {
		// An index > 0 corresponds to an offset into txn.Access. Check to
		// make sure the index is valid.
		if accountIdx > uint64(len(ac.Access)) {
			return basics.Address{}, fmt.Errorf("invalid Account reference %d exceeds length of tx.Access %d", accountIdx, len(ac.Access))
		}
		// And now check that the index refers to an Address
		rr := ac.Access[accountIdx-1]
		if rr.Address.IsZero() {
			return basics.Address{}, fmt.Errorf("address reference %d is not an Address in tx.Access", accountIdx)
		}
		return rr.Address, nil
	}

	// An index > 0 corresponds to an offset into txn.Accounts. Check to
	// make sure the index is valid.
	if accountIdx > uint64(len(ac.Accounts)) {
		return basics.Address{}, fmt.Errorf("invalid Account reference %d exceeds length of tx.Accounts %d", accountIdx, len(ac.Accounts))
	}

	// accountIdx must be in [1, len(ac.Accounts)]
	return ac.Accounts[accountIdx-1], nil
}

// IndexByAddress converts an address into an integer offset into [txn.Sender,
// tx.<list>[0], ...], returning the index at the first match. <list> is
// tx.Access or tx.Accounts. It returns an error if there is no such match.
func (ac *ApplicationCallTxnFields) IndexByAddress(target basics.Address, sender basics.Address) (uint64, error) {
	// Index 0 always corresponds to the sender
	if target == sender {
		return 0, nil
	}

	// Try ac.Access first. Remember only one of Access or Accounts can be set.
	if idx := slices.IndexFunc(ac.Access, func(rr ResourceRef) bool { return rr.Address == target }); idx != -1 {
		return uint64(idx) + 1, nil
	}

	// Otherwise we index into ac.Accounts
	if idx := slices.Index(ac.Accounts, target); idx != -1 {
		return uint64(idx) + 1, nil
	}

	return 0, fmt.Errorf("invalid Account reference %s does not appear in resource array", target)
}
