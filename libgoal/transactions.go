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

package libgoal

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// SignTransactionWithWallet signs the passed transaction with keys from the wallet associated with the passed walletHandle
func (c *Client) SignTransactionWithWallet(walletHandle, pw []byte, utx transactions.Transaction) (stx transactions.SignedTxn, err error) {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}

	// Sign the transaction
	resp, err := kmd.SignTransaction(walletHandle, pw, utx)
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
	txBytes := protocol.Encode(utx)
	addr, err := basics.UnmarshalChecksumAddress(signerAddr)
	if err != nil {
		return
	}
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}
	resp, err := kmd.MultisigSignTransaction(walletHandle, pw, txBytes, crypto.PublicKey(addr), partial)
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

	cparams, ok := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
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

	goOnlineTransaction := part.GenerateRegistrationTransaction(parsedFee, parsedFrstValid, parsedLastValid, leaseBytes, cparams)
	if cparams.SupportGenesisHash {
		var genHash crypto.Digest
		copy(genHash[:], params.GenesisHash)
		goOnlineTransaction.GenesisHash = genHash
		// Recompute the TXID
		goOnlineTransaction.ResetCaches()
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
		// Recompute the TXID
		goOnlineTransaction.ResetCaches()
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

	cparams, ok := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
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
		// Recompute the TXID
		goOfflineTransaction.ResetCaches()
	}

	// Default to the suggested fee, if the caller didn't supply it
	// Fee is tricky, should taken care last. We encode the final transaction to get the size post signing and encoding
	// Then, we multiply it by the suggested fee per byte.
	if fee == 0 {
		goOfflineTransaction.Fee = basics.MulAIntSaturate(basics.MicroAlgos{Raw: params.Fee}, goOfflineTransaction.EstimateEncodedSize())
		if goOfflineTransaction.Fee.Raw < cparams.MinTxnFee {
			goOfflineTransaction.Fee.Raw = cparams.MinTxnFee
		}
		// Recompute the TXID
		goOfflineTransaction.ResetCaches()
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

	cparams, ok := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
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
		// Recompute the TXID
		becomeNonparticipatingTransaction.ResetCaches()
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
		// Recompute the TXID
		becomeNonparticipatingTransaction.ResetCaches()
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

	cparams, ok := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
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

	// Recompute the TXID
	tx.ResetCaches()

	return tx, nil
}

// MakeUnsignedAssetCreateTx creates a tx template for creating
// an asset.
//
// Call FillUnsignedTxTemplate afterwards to fill out common fields in
// the resulting transaction template.
func (c *Client) MakeUnsignedAssetCreateTx(total uint64, defaultFrozen bool, manager string, reserve string, freeze string, clawback string, unitName string, assetName string, url string, metadataHash []byte) (transactions.Transaction, error) {
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

	cparams, ok := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
	if !ok {
		return transactions.Transaction{}, errors.New("unknown consensus version")
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
