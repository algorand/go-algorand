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
func (c *Client) MakeUnsignedGoOnlineTx(address string, part *account.Participation, round, txValidRounds, fee uint64) (transactions.Transaction, error) {
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

	// Determine the last round this tx will be valid
	if round == 0 {
		round = params.LastRound + 1
	}

	cparams, ok := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
	if !ok {
		return transactions.Transaction{}, errors.New("unknown consensus version")
	}

	if txValidRounds == 0 {
		txValidRounds = cparams.MaxTxnLife
	}

	// Choose which participation keys to go online with;
	// need to do this after filling in the round number.
	if part == nil {
		bestPart, err := c.chooseParticipation(parsedAddr, basics.Round(round))
		if err != nil {
			return transactions.Transaction{}, err
		}
		part = &bestPart
	}

	parsedRound := basics.Round(round)
	parsedTXValidRounds := basics.Round(txValidRounds)

	lastRound := parsedRound + parsedTXValidRounds
	parsedFee := basics.MicroAlgos{Raw: fee}

	goOnlineTransaction := part.GenerateRegistrationTransaction(parsedFee, parsedRound, lastRound, cparams)
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
func (c *Client) MakeUnsignedGoOfflineTx(address string, round, txValidRounds, fee uint64) (transactions.Transaction, error) {
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

	// Determine the last round this tx will be valid
	if round == 0 {
		round = params.LastRound + 1
	}

	if txValidRounds == 0 {
		txValidRounds = cparams.MaxTxnLife
	}

	parsedRound := basics.Round(round)
	parsedTXValidRounds := basics.Round(txValidRounds)
	lastRound := parsedRound + parsedTXValidRounds
	parsedFee := basics.MicroAlgos{Raw: fee}

	goOfflineTransaction := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:     parsedAddr,
			Fee:        parsedFee,
			FirstValid: parsedRound,
			LastValid:  lastRound,
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

// FillUnsignedTxTemplate fills in header fields in a partially-filled-in transaction.
func (c *Client) FillUnsignedTxTemplate(sender string, firstValid, numValidRounds, fee uint64, tx transactions.Transaction) (transactions.Transaction, error) {
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

	// Determine the last round this tx will be valid
	if firstValid == 0 {
		firstValid = params.LastRound + 1
	}

	if numValidRounds == 0 {
		numValidRounds = cparams.MaxTxnLife
	}

	parsedFirstValid := basics.Round(firstValid)
	parsedLastValid := basics.Round(firstValid + numValidRounds)
	parsedFee := basics.MicroAlgos{Raw: fee}

	tx.Header = transactions.Header{
		Sender:     parsedAddr,
		Fee:        parsedFee,
		FirstValid: parsedFirstValid,
		LastValid:  parsedLastValid,
	}

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

// MakeUnsignedCurrencyCreateTx creates a tx template for creating
// a currency.
//
// Call FillUnsignedTxTemplate afterwards to fill out common fields in
// the resulting transaction template.
func (c *Client) MakeUnsignedCurrencyCreateTx(total uint64, defaultFrozen bool, manager string, reserve string, freeze string, clawback string, unitName string) (transactions.Transaction, error) {
	var tx transactions.Transaction
	var err error

	tx.Type = protocol.CurrencyConfigTx
	tx.CurrencyParams = basics.CurrencyParams{
		Total:         total,
		DefaultFrozen: defaultFrozen,
	}

	if manager != "" {
		tx.CurrencyParams.Manager, err = basics.UnmarshalChecksumAddress(manager)
		if err != nil {
			return tx, err
		}
	}

	if reserve != "" {
		tx.CurrencyParams.Reserve, err = basics.UnmarshalChecksumAddress(reserve)
		if err != nil {
			return tx, err
		}
	}

	if freeze != "" {
		tx.CurrencyParams.Freeze, err = basics.UnmarshalChecksumAddress(freeze)
		if err != nil {
			return tx, err
		}
	}

	if clawback != "" {
		tx.CurrencyParams.Clawback, err = basics.UnmarshalChecksumAddress(clawback)
		if err != nil {
			return tx, err
		}
	}

	if len(unitName) > len(tx.CurrencyParams.UnitName) {
		return tx, fmt.Errorf("currency unit name %s too long (max %d bytes)", unitName, len(tx.CurrencyParams.UnitName))
	}
	copy(tx.CurrencyParams.UnitName[:], []byte(unitName))

	return tx, nil
}

// MakeUnsignedCurrencyDestroyTx creates a tx template for destroying
// a currency.
//
// Call FillUnsignedTxTemplate afterwards to fill out common fields in
// the resulting transaction template.
func (c *Client) MakeUnsignedCurrencyDestroyTx(creator string, index uint64) (transactions.Transaction, error) {
	var tx transactions.Transaction
	var err error

	tx.Type = protocol.CurrencyConfigTx
	tx.ConfigCurrency.Index = index
	tx.ConfigCurrency.Creator, err = basics.UnmarshalChecksumAddress(creator)
	if err != nil {
		return tx, err
	}

	return tx, nil
}

// MakeUnsignedCurrencyConfigTx creates a tx template for changing the
// keys for a currency.  A nil pointer for a new key argument means no
// change to existing key.  An empty string means a zero key (which
// cannot be changed after becoming zero).
//
// Call FillUnsignedTxTemplate afterwards to fill out common fields in
// the resulting transaction template.
func (c *Client) MakeUnsignedCurrencyConfigTx(creator string, index uint64, newManager *string, newReserve *string, newFreeze *string, newClawback *string) (transactions.Transaction, error) {
	var tx transactions.Transaction
	var err error

	// Fetch the current state, to fill in as a template
	current, err := c.AccountInformation(creator)
	if err != nil {
		return tx, err
	}

	params, ok := current.CurrencyParams[index]
	if !ok {
		return tx, fmt.Errorf("currency ID %d not found in account %s", index, creator)
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

	tx.Type = protocol.CurrencyConfigTx
	tx.ConfigCurrency.Index = index
	tx.ConfigCurrency.Creator, err = basics.UnmarshalChecksumAddress(creator)
	if err != nil {
		return tx, err
	}

	if *newManager != "" {
		tx.CurrencyParams.Manager, err = basics.UnmarshalChecksumAddress(*newManager)
		if err != nil {
			return tx, err
		}
	}

	if *newReserve != "" {
		tx.CurrencyParams.Reserve, err = basics.UnmarshalChecksumAddress(*newReserve)
		if err != nil {
			return tx, err
		}
	}

	if *newFreeze != "" {
		tx.CurrencyParams.Freeze, err = basics.UnmarshalChecksumAddress(*newFreeze)
		if err != nil {
			return tx, err
		}
	}

	if *newClawback != "" {
		tx.CurrencyParams.Clawback, err = basics.UnmarshalChecksumAddress(*newClawback)
		if err != nil {
			return tx, err
		}
	}

	return tx, nil
}

// MakeUnsignedCurrencySendTx creates a tx template for sending currency.
// To allocate a slot for a particular currency, send a zero amount to self.
//
// Call FillUnsignedTxTemplate afterwards to fill out common fields in
// the resulting transaction template.
func (c *Client) MakeUnsignedCurrencySendTx(creator string, index uint64, amount uint64, recipient string, closeTo string, senderForClawback string) (transactions.Transaction, error) {
	var tx transactions.Transaction
	var err error

	tx.Type = protocol.CurrencyTransferTx
	tx.CurrencyAmount = amount
	tx.XferCurrency.Index = index
	tx.XferCurrency.Creator, err = basics.UnmarshalChecksumAddress(creator)
	if err != nil {
		return tx, err
	}

	if recipient != "" {
		tx.CurrencyReceiver, err = basics.UnmarshalChecksumAddress(recipient)
		if err != nil {
			return tx, err
		}
	}

	if closeTo != "" {
		tx.CurrencyCloseTo, err = basics.UnmarshalChecksumAddress(closeTo)
		if err != nil {
			return tx, err
		}
	}

	if senderForClawback != "" {
		tx.CurrencySender, err = basics.UnmarshalChecksumAddress(senderForClawback)
		if err != nil {
			return tx, err
		}
	}

	return tx, nil
}

// MakeUnsignedCurrencyFreezeTx creates a tx template for freezing currency.
//
// Call FillUnsignedTxTemplate afterwards to fill out common fields in
// the resulting transaction template.
func (c *Client) MakeUnsignedCurrencyFreezeTx(creator string, index uint64, accountToChange string, newFreezeSetting bool) (transactions.Transaction, error) {
	var tx transactions.Transaction
	var err error

	tx.Type = protocol.CurrencyFreezeTx
	tx.FreezeCurrency.Index = index
	tx.FreezeCurrency.Creator, err = basics.UnmarshalChecksumAddress(creator)
	if err != nil {
		return tx, err
	}

	tx.FreezeAccount, err = basics.UnmarshalChecksumAddress(accountToChange)
	if err != nil {
		return tx, err
	}

	tx.CurrencyFrozen = newFreezeSetting

	return tx, nil
}
