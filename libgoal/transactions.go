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

package libgoal

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

var emptySchema = basics.StateSchema{}

// SignTransactionWithWallet signs the passed transaction with keys from the wallet associated with the passed walletHandle
func (c *Client) SignTransactionWithWallet(walletHandle, pw []byte, utx transactions.Transaction) (stx transactions.SignedTxn, err error) {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}

	// Sign the transaction
	resp, err := kmd.SignTransaction(walletHandle, pw, crypto.PublicKey{}, utx)
	if err != nil {
		return
	}

	// Decode the SignedTxn
	err = protocol.Decode(resp.SignedTransaction, &stx)
	return
}

// SignTransactionWithWalletAndSigner signs the passed transaction under a specific signer (which may differ from the sender's address). This is necessary after an account has been rekeyed.
// If signerAddr is the empty string, just infer spending key from the sender address.
func (c *Client) SignTransactionWithWalletAndSigner(walletHandle, pw []byte, signerAddr string, utx transactions.Transaction) (stx transactions.SignedTxn, err error) {
	if signerAddr == "" {
		return c.SignTransactionWithWallet(walletHandle, pw, utx)
	}

	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}

	authaddr, err := basics.UnmarshalChecksumAddress(signerAddr)
	if err != nil {
		return
	}
	// Sign the transaction
	resp, err := kmd.SignTransaction(walletHandle, pw, crypto.PublicKey(authaddr), utx)
	if err != nil {
		return
	}

	// Decode the SignedTxn
	err = protocol.Decode(resp.SignedTransaction, &stx)
	return
}

// SignProgramWithWallet signs the passed transaction with keys from the wallet associated with the passed walletHandle
func (c *Client) SignProgramWithWallet(walletHandle, pw []byte, addr string, program []byte) (signature crypto.Signature, err error) {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}

	// Sign the transaction
	resp, err := kmd.SignProgram(walletHandle, pw, addr, program)
	if err != nil {
		return
	}

	copy(signature[:], resp.Signature)
	return
}

// MultisigSignTransactionWithWallet creates a multisig (or adds to an existing partial multisig, if one is provided), signing with the key corresponding to the given address and using the specified wallet
// TODO instead of returning MultisigSigs, accept and return blobs
func (c *Client) MultisigSignTransactionWithWallet(walletHandle, pw []byte, utx transactions.Transaction, signerAddr string, partial crypto.MultisigSig) (msig crypto.MultisigSig, err error) {
	txBytes := protocol.Encode(&utx)
	addr, err := basics.UnmarshalChecksumAddress(signerAddr)
	if err != nil {
		return
	}
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}
	resp, err := kmd.MultisigSignTransaction(walletHandle, pw, txBytes, crypto.PublicKey(addr), partial, crypto.Digest{})
	if err != nil {
		return
	}
	err = protocol.Decode(resp.Multisig, &msig)
	return
}

// MultisigSignTransactionWithWalletAndSigner creates a multisig (or adds to an existing partial multisig, if one is provided), signing with the key corresponding to the given address and using the specified wallet
func (c *Client) MultisigSignTransactionWithWalletAndSigner(walletHandle, pw []byte, utx transactions.Transaction, signerAddr string, partial crypto.MultisigSig, signerMsig string) (msig crypto.MultisigSig, err error) {
	txBytes := protocol.Encode(&utx)
	addr, err := basics.UnmarshalChecksumAddress(signerAddr)
	if err != nil {
		return
	}
	msigAddr, err := basics.UnmarshalChecksumAddress(signerMsig)
	if err != nil {
		return
	}
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}
	resp, err := kmd.MultisigSignTransaction(walletHandle, pw, txBytes, crypto.PublicKey(addr), partial, crypto.Digest(msigAddr))
	if err != nil {
		return
	}
	err = protocol.Decode(resp.Multisig, &msig)
	return
}

// MultisigSignProgramWithWallet creates a multisig (or adds to an existing partial multisig, if one is provided), signing with the key corresponding to the given address and using the specified wallet
func (c *Client) MultisigSignProgramWithWallet(walletHandle, pw, program []byte, signerAddr string, partial crypto.MultisigSig) (msig crypto.MultisigSig, err error) {
	addr, err := basics.UnmarshalChecksumAddress(signerAddr)
	if err != nil {
		return
	}
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}
	msigAddr, err := crypto.MultisigAddrGenWithSubsigs(partial.Version, partial.Threshold, partial.Subsigs)
	if err != nil {
		return
	}
	resp, err := kmd.MultisigSignProgram(walletHandle, pw, basics.Address(msigAddr).String(), program, crypto.PublicKey(addr), partial)
	if err != nil {
		return
	}
	err = protocol.Decode(resp.Multisig, &msig)
	return
}

// BroadcastTransaction broadcasts a signed transaction to the network using algod
func (c *Client) BroadcastTransaction(stx transactions.SignedTxn) (txid string, err error) {
	algod, err := c.ensureAlgodClient()
	if err != nil {
		return
	}
	resp, err := algod.SendRawTransaction(stx)
	if err != nil {
		return
	}
	return resp.TxID, nil
}

// BroadcastTransactionGroup broadcasts a signed transaction group to the network using algod
func (c *Client) BroadcastTransactionGroup(txgroup []transactions.SignedTxn) error {
	algod, err := c.ensureAlgodClient()
	if err != nil {
		return err
	}
	return algod.SendRawTransactionGroup(txgroup)
}

// SignAndBroadcastTransaction signs the unsigned transaction with keys from the default wallet, and broadcasts it
func (c *Client) SignAndBroadcastTransaction(walletHandle, pw []byte, utx transactions.Transaction) (txid string, err error) {
	// Sign the transaction
	stx, err := c.SignTransactionWithWallet(walletHandle, pw, utx)
	if err != nil {
		return
	}

	// Broadcast the transaction
	return c.BroadcastTransaction(stx)
}

// MakeUnsignedGoOnlineTx creates a transaction that will bring an address online using available participation keys
func (c *Client) MakeUnsignedGoOnlineTx(address string, part *account.Participation, firstValid, lastValid, fee uint64, leaseBytes [32]byte) (transactions.Transaction, error) {
	// Parse the address
	parsedAddr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return transactions.Transaction{}, err
	}

	// Get current round, protocol, genesis ID
	params, err := c.SuggestedParams()
	if err != nil {
		return transactions.Transaction{}, err
	}

	cparams, ok := c.consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
	if !ok {
		return transactions.Transaction{}, errors.New("unknown consensus version")
	}

	firstValid, lastValid, err = computeValidityRounds(firstValid, lastValid, 0, params.LastRound, cparams.MaxTxnLife)
	if err != nil {
		return transactions.Transaction{}, err
	}

	// Choose which participation keys to go online with;
	// need to do this after filling in the round number.
	if part == nil {
		bestPart, err := c.chooseParticipation(parsedAddr, basics.Round(firstValid))
		if err != nil {
			return transactions.Transaction{}, err
		}
		part = &bestPart
	}

	parsedFrstValid := basics.Round(firstValid)
	parsedLastValid := basics.Round(lastValid)
	parsedFee := basics.MicroAlgos{Raw: fee}

	goOnlineTransaction := part.GenerateRegistrationTransaction(parsedFee, parsedFrstValid, parsedLastValid, leaseBytes)
	if cparams.SupportGenesisHash {
		var genHash crypto.Digest
		copy(genHash[:], params.GenesisHash)
		goOnlineTransaction.GenesisHash = genHash
	}

	// Default to the suggested fee, if the caller didn't supply it
	// Fee is tricky, should taken care last. We encode the final
	// transaction to get the size post signing and encoding.
	// Then, we multiply it by the suggested fee per byte.
	if fee == 0 {
		goOnlineTransaction.Fee = basics.MulAIntSaturate(basics.MicroAlgos{Raw: params.Fee}, goOnlineTransaction.EstimateEncodedSize())
		if goOnlineTransaction.Fee.Raw < cparams.MinTxnFee {
			goOnlineTransaction.Fee.Raw = cparams.MinTxnFee
		}
	}
	return goOnlineTransaction, nil
}

// MakeUnsignedGoOfflineTx creates a transaction that will bring an address offline
func (c *Client) MakeUnsignedGoOfflineTx(address string, firstValid, lastValid, fee uint64, leaseBytes [32]byte) (transactions.Transaction, error) {
	// Parse the address
	parsedAddr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return transactions.Transaction{}, err
	}

	params, err := c.SuggestedParams()
	if err != nil {
		return transactions.Transaction{}, err
	}

	cparams, ok := c.consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
	if !ok {
		return transactions.Transaction{}, errors.New("unknown consensus version")
	}

	firstValid, lastValid, err = computeValidityRounds(firstValid, lastValid, 0, params.LastRound, cparams.MaxTxnLife)
	if err != nil {
		return transactions.Transaction{}, err
	}

	parsedFirstRound := basics.Round(firstValid)
	parsedLastRound := basics.Round(lastValid)
	parsedFee := basics.MicroAlgos{Raw: fee}

	goOfflineTransaction := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:     parsedAddr,
			Fee:        parsedFee,
			FirstValid: parsedFirstRound,
			LastValid:  parsedLastRound,
			Lease:      leaseBytes,
		},
	}
	if cparams.SupportGenesisHash {
		var genHash crypto.Digest
		copy(genHash[:], params.GenesisHash)
		goOfflineTransaction.GenesisHash = genHash
	}

	// Default to the suggested fee, if the caller didn't supply it
	// Fee is tricky, should taken care last. We encode the final transaction to get the size post signing and encoding
	// Then, we multiply it by the suggested fee per byte.
	if fee == 0 {
		goOfflineTransaction.Fee = basics.MulAIntSaturate(basics.MicroAlgos{Raw: params.Fee}, goOfflineTransaction.EstimateEncodedSize())
		if goOfflineTransaction.Fee.Raw < cparams.MinTxnFee {
			goOfflineTransaction.Fee.Raw = cparams.MinTxnFee
		}
	}
	return goOfflineTransaction, nil
}

// MakeUnsignedBecomeNonparticipatingTx creates a transaction that will mark an account as non-participating
func (c *Client) MakeUnsignedBecomeNonparticipatingTx(address string, firstValid, lastValid, fee uint64) (transactions.Transaction, error) {
	// Parse the address
	parsedAddr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return transactions.Transaction{}, err
	}

	params, err := c.SuggestedParams()
	if err != nil {
		return transactions.Transaction{}, err
	}

	cparams, ok := c.consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
	if !ok {
		return transactions.Transaction{}, errors.New("unknown consensus version")
	}

	firstValid, lastValid, err = computeValidityRounds(firstValid, lastValid, 0, params.LastRound, cparams.MaxTxnLife)
	if err != nil {
		return transactions.Transaction{}, err
	}

	parsedFirstRound := basics.Round(firstValid)
	parsedLastRound := basics.Round(lastValid)
	parsedFee := basics.MicroAlgos{Raw: fee}

	becomeNonparticipatingTransaction := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:     parsedAddr,
			Fee:        parsedFee,
			FirstValid: parsedFirstRound,
			LastValid:  parsedLastRound,
		},
	}
	if cparams.SupportGenesisHash {
		var genHash crypto.Digest
		copy(genHash[:], params.GenesisHash)
		becomeNonparticipatingTransaction.GenesisHash = genHash
	}
	becomeNonparticipatingTransaction.KeyregTxnFields.Nonparticipation = true

	// Default to the suggested fee, if the caller didn't supply it
	// Fee is tricky, should taken care last. We encode the final transaction to get the size post signing and encoding
	// Then, we multiply it by the suggested fee per byte.
	if fee == 0 {
		becomeNonparticipatingTransaction.Fee = basics.MulAIntSaturate(basics.MicroAlgos{Raw: params.Fee}, becomeNonparticipatingTransaction.EstimateEncodedSize())
		if becomeNonparticipatingTransaction.Fee.Raw < cparams.MinTxnFee {
			becomeNonparticipatingTransaction.Fee.Raw = cparams.MinTxnFee
		}
	}
	return becomeNonparticipatingTransaction, nil
}

// FillUnsignedTxTemplate fills in header fields in a partially-filled-in transaction.
func (c *Client) FillUnsignedTxTemplate(sender string, firstValid, lastValid, fee uint64, tx transactions.Transaction) (transactions.Transaction, error) {
	// Parse the address
	parsedAddr, err := basics.UnmarshalChecksumAddress(sender)
	if err != nil {
		return transactions.Transaction{}, err
	}

	params, err := c.SuggestedParams()
	if err != nil {
		return transactions.Transaction{}, err
	}

	cparams, ok := c.consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
	if !ok {
		return transactions.Transaction{}, errors.New("unknown consensus version")
	}

	firstValid, lastValid, err = computeValidityRounds(firstValid, lastValid, 0, params.LastRound, cparams.MaxTxnLife)
	if err != nil {
		return transactions.Transaction{}, err
	}

	parsedFee := basics.MicroAlgos{Raw: fee}

	tx.Header.Sender = parsedAddr
	tx.Header.Fee = parsedFee
	tx.Header.FirstValid = basics.Round(firstValid)
	tx.Header.LastValid = basics.Round(lastValid)

	if cparams.SupportGenesisHash {
		var genHash crypto.Digest
		copy(genHash[:], params.GenesisHash)
		tx.GenesisHash = genHash
	}

	// Default to the suggested fee, if the caller didn't supply it
	// Fee is tricky, should taken care last. We encode the final
	// transaction to get the size post signing and encoding.
	// Then, we multiply it by the suggested fee per byte.
	if fee == 0 {
		tx.Fee = basics.MulAIntSaturate(basics.MicroAlgos{Raw: params.Fee}, tx.EstimateEncodedSize())
		if tx.Fee.Raw < cparams.MinTxnFee {
			tx.Fee.Raw = cparams.MinTxnFee
		}
	}

	return tx, nil
}

// MakeUnsignedAppCreateTx makes a transaction for creating an application
func (c *Client) MakeUnsignedAppCreateTx(onComplete transactions.OnCompletion, approvalProg []byte, clearProg []byte, globalSchema basics.StateSchema, localSchema basics.StateSchema, appArgs [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64, extrapages uint32) (tx transactions.Transaction, err error) {
	return c.MakeUnsignedApplicationCallTx(0, appArgs, accounts, foreignApps, foreignAssets, onComplete, approvalProg, clearProg, globalSchema, localSchema, extrapages)
}

// MakeUnsignedAppUpdateTx makes a transaction for updating an application's programs
func (c *Client) MakeUnsignedAppUpdateTx(appIdx uint64, appArgs [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64, approvalProg []byte, clearProg []byte) (tx transactions.Transaction, err error) {
	return c.MakeUnsignedApplicationCallTx(appIdx, appArgs, accounts, foreignApps, foreignAssets, transactions.UpdateApplicationOC, approvalProg, clearProg, emptySchema, emptySchema, 0)
}

// MakeUnsignedAppDeleteTx makes a transaction for deleting an application
func (c *Client) MakeUnsignedAppDeleteTx(appIdx uint64, appArgs [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64) (tx transactions.Transaction, err error) {
	return c.MakeUnsignedApplicationCallTx(appIdx, appArgs, accounts, foreignApps, foreignAssets, transactions.DeleteApplicationOC, nil, nil, emptySchema, emptySchema, 0)
}

// MakeUnsignedAppOptInTx makes a transaction for opting in to (allocating
// some account-specific state for) an application
func (c *Client) MakeUnsignedAppOptInTx(appIdx uint64, appArgs [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64) (tx transactions.Transaction, err error) {
	return c.MakeUnsignedApplicationCallTx(appIdx, appArgs, accounts, foreignApps, foreignAssets, transactions.OptInOC, nil, nil, emptySchema, emptySchema, 0)
}

// MakeUnsignedAppCloseOutTx makes a transaction for closing out of
// (deallocating all account-specific state for) an application
func (c *Client) MakeUnsignedAppCloseOutTx(appIdx uint64, appArgs [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64) (tx transactions.Transaction, err error) {
	return c.MakeUnsignedApplicationCallTx(appIdx, appArgs, accounts, foreignApps, foreignAssets, transactions.CloseOutOC, nil, nil, emptySchema, emptySchema, 0)
}

// MakeUnsignedAppClearStateTx makes a transaction for clearing out all
// account-specific state for an application. It may not be rejected by the
// application's logic.
func (c *Client) MakeUnsignedAppClearStateTx(appIdx uint64, appArgs [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64) (tx transactions.Transaction, err error) {
	return c.MakeUnsignedApplicationCallTx(appIdx, appArgs, accounts, foreignApps, foreignAssets, transactions.ClearStateOC, nil, nil, emptySchema, emptySchema, 0)
}

// MakeUnsignedAppNoOpTx makes a transaction for interacting with an existing
// application, potentially updating any account-specific local state and
// global state associated with it.
func (c *Client) MakeUnsignedAppNoOpTx(appIdx uint64, appArgs [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64) (tx transactions.Transaction, err error) {
	return c.MakeUnsignedApplicationCallTx(appIdx, appArgs, accounts, foreignApps, foreignAssets, transactions.NoOpOC, nil, nil, emptySchema, emptySchema, 0)
}

// MakeUnsignedApplicationCallTx is a helper for the above ApplicationCall
// transaction constructors. A fully custom ApplicationCall transaction may
// be constructed using this method.
func (c *Client) MakeUnsignedApplicationCallTx(appIdx uint64, appArgs [][]byte, accounts []string, foreignApps []uint64, foreignAssets []uint64, onCompletion transactions.OnCompletion, approvalProg []byte, clearProg []byte, globalSchema basics.StateSchema, localSchema basics.StateSchema, extrapages uint32) (tx transactions.Transaction, err error) {
	tx.Type = protocol.ApplicationCallTx
	tx.ApplicationID = basics.AppIndex(appIdx)
	tx.OnCompletion = onCompletion

	tx.ApplicationArgs = appArgs
	tx.Accounts, err = parseTxnAccounts(accounts)
	if err != nil {
		return tx, err
	}

	tx.ForeignApps = parseTxnForeignApps(foreignApps)
	tx.ForeignAssets = parseTxnForeignAssets(foreignAssets)
	tx.ApprovalProgram = approvalProg
	tx.ClearStateProgram = clearProg
	tx.LocalStateSchema = localSchema
	tx.GlobalStateSchema = globalSchema
	tx.ExtraProgramPages = extrapages

	return tx, nil
}

func parseTxnAccounts(accounts []string) (parsed []basics.Address, err error) {
	for _, acct := range accounts {
		addr, err := basics.UnmarshalChecksumAddress(acct)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, addr)
	}
	return
}

func parseTxnForeignApps(foreignApps []uint64) (parsed []basics.AppIndex) {
	for _, aidx := range foreignApps {
		parsed = append(parsed, basics.AppIndex(aidx))
	}
	return
}

func parseTxnForeignAssets(foreignAssets []uint64) (parsed []basics.AssetIndex) {
	for _, aidx := range foreignAssets {
		parsed = append(parsed, basics.AssetIndex(aidx))
	}
	return
}

// MakeUnsignedAssetCreateTx creates a tx template for creating
// an asset.
//
// Call FillUnsignedTxTemplate afterwards to fill out common fields in
// the resulting transaction template.
func (c *Client) MakeUnsignedAssetCreateTx(total uint64, defaultFrozen bool, manager string, reserve string, freeze string, clawback string, unitName string, assetName string, url string, metadataHash []byte, decimals uint32) (transactions.Transaction, error) {
	var tx transactions.Transaction
	var err error

	tx.Type = protocol.AssetConfigTx
	tx.AssetParams = basics.AssetParams{
		Total:         total,
		DefaultFrozen: defaultFrozen,
	}

	if manager != "" {
		tx.AssetParams.Manager, err = basics.UnmarshalChecksumAddress(manager)
		if err != nil {
			return tx, err
		}
	}

	if reserve != "" {
		tx.AssetParams.Reserve, err = basics.UnmarshalChecksumAddress(reserve)
		if err != nil {
			return tx, err
		}
	}

	if freeze != "" {
		tx.AssetParams.Freeze, err = basics.UnmarshalChecksumAddress(freeze)
		if err != nil {
			return tx, err
		}
	}

	if clawback != "" {
		tx.AssetParams.Clawback, err = basics.UnmarshalChecksumAddress(clawback)
		if err != nil {
			return tx, err
		}
	}

	// Get consensus params so we can get max field lengths
	params, err := c.SuggestedParams()
	if err != nil {
		return transactions.Transaction{}, err
	}

	cparams, ok := c.consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
	if !ok {
		return transactions.Transaction{}, errors.New("unknown consensus version")
	}

	// If assets are not yet enabled, lookup the base parameters to allow creating assets during catchup
	if !cparams.Asset {
		cparams, ok = c.consensus[protocol.ConsensusCurrentVersion]

		if !ok {
			return transactions.Transaction{}, errors.New("unknown consensus version")
		}
	}

	if len(url) > cparams.MaxAssetURLBytes {
		return tx, fmt.Errorf("asset url %s is too long (max %d bytes)", url, cparams.MaxAssetURLBytes)
	}
	tx.AssetParams.URL = url

	if len(metadataHash) > len(tx.AssetParams.MetadataHash) {
		return tx, fmt.Errorf("asset metadata hash %x too long (max %d bytes)", metadataHash, len(tx.AssetParams.MetadataHash))
	}
	copy(tx.AssetParams.MetadataHash[:], metadataHash)

	if len(unitName) > cparams.MaxAssetUnitNameBytes {
		return tx, fmt.Errorf("asset unit name %s too long (max %d bytes)", unitName, cparams.MaxAssetUnitNameBytes)
	}
	tx.AssetParams.UnitName = unitName

	if len(assetName) > cparams.MaxAssetNameBytes {
		return tx, fmt.Errorf("asset name %s too long (max %d bytes)", assetName, cparams.MaxAssetNameBytes)
	}
	tx.AssetParams.AssetName = assetName

	if decimals > cparams.MaxAssetDecimals {
		return tx, fmt.Errorf("asset decimal precision too high (max %d)", cparams.MaxAssetDecimals)
	}
	tx.AssetParams.Decimals = decimals

	return tx, nil
}

// MakeUnsignedAssetDestroyTx creates a tx template for destroying
// an asset.
//
// Call FillUnsignedTxTemplate afterwards to fill out common fields in
// the resulting transaction template.
func (c *Client) MakeUnsignedAssetDestroyTx(index uint64) (transactions.Transaction, error) {
	var tx transactions.Transaction
	tx.Type = protocol.AssetConfigTx
	tx.ConfigAsset = basics.AssetIndex(index)
	return tx, nil
}

// MakeUnsignedAssetConfigTx creates a tx template for changing the
// keys for an asset.  A nil pointer for a new key argument means no
// change to existing key.  An empty string means a zero key (which
// cannot be changed after becoming zero).
//
// Call FillUnsignedTxTemplate afterwards to fill out common fields in
// the resulting transaction template.
func (c *Client) MakeUnsignedAssetConfigTx(creator string, index uint64, newManager *string, newReserve *string, newFreeze *string, newClawback *string) (transactions.Transaction, error) {
	var tx transactions.Transaction
	var err error
	var ok bool

	// If the creator was passed in blank, look up asset info by index
	var params v1.AssetParams
	if creator == "" {
		params, err = c.AssetInformation(index)
		if err != nil {
			return tx, err
		}
	} else {
		// Fetch the current state, to fill in as a template
		current, err := c.AccountInformation(creator)
		if err != nil {
			return tx, err
		}

		params, ok = current.AssetParams[index]
		if !ok {
			return tx, fmt.Errorf("asset ID %d not found in account %s", index, creator)
		}
	}

	if newManager == nil {
		newManager = &params.ManagerAddr
	}

	if newReserve == nil {
		newReserve = &params.ReserveAddr
	}

	if newFreeze == nil {
		newFreeze = &params.FreezeAddr
	}

	if newClawback == nil {
		newClawback = &params.ClawbackAddr
	}

	tx.Type = protocol.AssetConfigTx
	tx.ConfigAsset = basics.AssetIndex(index)

	if *newManager != "" {
		tx.AssetParams.Manager, err = basics.UnmarshalChecksumAddress(*newManager)
		if err != nil {
			return tx, err
		}
	}

	if *newReserve != "" {
		tx.AssetParams.Reserve, err = basics.UnmarshalChecksumAddress(*newReserve)
		if err != nil {
			return tx, err
		}
	}

	if *newFreeze != "" {
		tx.AssetParams.Freeze, err = basics.UnmarshalChecksumAddress(*newFreeze)
		if err != nil {
			return tx, err
		}
	}

	if *newClawback != "" {
		tx.AssetParams.Clawback, err = basics.UnmarshalChecksumAddress(*newClawback)
		if err != nil {
			return tx, err
		}
	}

	return tx, nil
}

// MakeUnsignedAssetSendTx creates a tx template for sending assets.
// To allocate a slot for a particular asset, send a zero amount to self.
//
// Call FillUnsignedTxTemplate afterwards to fill out common fields in
// the resulting transaction template.
func (c *Client) MakeUnsignedAssetSendTx(index uint64, amount uint64, recipient string, closeTo string, senderForClawback string) (transactions.Transaction, error) {
	var tx transactions.Transaction
	var err error

	tx.Type = protocol.AssetTransferTx
	tx.AssetAmount = amount
	tx.XferAsset = basics.AssetIndex(index)

	if recipient != "" {
		tx.AssetReceiver, err = basics.UnmarshalChecksumAddress(recipient)
		if err != nil {
			return tx, err
		}
	}

	if closeTo != "" {
		tx.AssetCloseTo, err = basics.UnmarshalChecksumAddress(closeTo)
		if err != nil {
			return tx, err
		}
	}

	if senderForClawback != "" {
		tx.AssetSender, err = basics.UnmarshalChecksumAddress(senderForClawback)
		if err != nil {
			return tx, err
		}
	}

	return tx, nil
}

// MakeUnsignedAssetFreezeTx creates a tx template for freezing assets.
//
// Call FillUnsignedTxTemplate afterwards to fill out common fields in
// the resulting transaction template.
func (c *Client) MakeUnsignedAssetFreezeTx(index uint64, accountToChange string, newFreezeSetting bool) (transactions.Transaction, error) {
	var tx transactions.Transaction
	var err error

	tx.Type = protocol.AssetFreezeTx
	tx.FreezeAsset = basics.AssetIndex(index)

	tx.FreezeAccount, err = basics.UnmarshalChecksumAddress(accountToChange)
	if err != nil {
		return tx, err
	}

	tx.AssetFrozen = newFreezeSetting

	return tx, nil
}

// GroupID computes the group ID for a group of transactions.
func (c *Client) GroupID(txgroup []transactions.Transaction) (gid crypto.Digest, err error) {
	var group transactions.TxGroup
	for _, tx := range txgroup {
		if !tx.Group.IsZero() {
			err = fmt.Errorf("tx %v already has a group %v", tx, tx.Group)
			return
		}

		group.TxGroupHashes = append(group.TxGroupHashes, crypto.HashObj(tx))
	}

	return crypto.HashObj(group), nil
}
