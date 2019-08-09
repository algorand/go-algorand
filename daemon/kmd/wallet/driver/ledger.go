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

package driver

import (
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/daemon/kmd/wallet"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const (
	ledgerWalletDriverName    = "ledger"
	ledgerWalletDriverVersion = 1
)

var ledgerWalletSupportedTxs = []protocol.TxType{protocol.PaymentTx, protocol.KeyRegistrationTx}

// LedgerWalletDriver provides access to a hardware wallet on the
// Ledger Nano S device.  The device must run the Algorand wallet
// application from https://github.com/algorand/ledger-app-algorand
type LedgerWalletDriver struct {
	wallets map[string]*LedgerWallet
}

// LedgerWallet represents a particular wallet under the
// LedgerWalletDriver.  The lock prevents concurrent access
// to the USB device.
type LedgerWallet struct {
	mu  deadlock.Mutex
	dev LedgerUSB
}

// CreateWallet implements the Driver interface.  There is
// currently no way to create new wallet keys; there is one
// key in a hardware wallet, derived from the device master
// secret.  We could, in principle, derive multiple keys.
// This is not supported at the moment.
func (lwd *LedgerWalletDriver) CreateWallet(name []byte, id []byte, pw []byte, mdk crypto.MasterDerivationKey) error {
	return errNotSupported
}

// FetchWallet looks up a wallet by ID and returns it, failing if there's more
// than one wallet with the given ID
func (lwd *LedgerWalletDriver) FetchWallet(id []byte) (w wallet.Wallet, err error) {
	lw, ok := lwd.wallets[string(id)]
	if !ok {
		return nil, errWalletNotFound
	}

	return lw, nil
}

// InitWithConfig accepts a driver configuration.  Currently, the Ledger
// driver does not have any configuration parameters.  However, we use
// this to enumerate the USB devices.
func (lwd *LedgerWalletDriver) InitWithConfig(cfg config.KMDConfig) error {
	devs, err := LedgerEnumerate()
	if err != nil {
		return err
	}

	lwd.wallets = make(map[string]*LedgerWallet)
	for _, dev := range devs {
		id := dev.USBInfo().Path
		lwd.wallets[id] = &LedgerWallet{
			dev: dev,
		}
	}
	return nil
}

// ListWalletMetadatas returns all wallets supported by this driver.
func (lwd *LedgerWalletDriver) ListWalletMetadatas() (metadatas []wallet.Metadata, err error) {
	for _, w := range lwd.wallets {
		md, err := w.Metadata()
		if err != nil {
			return nil, err
		}

		metadatas = append(metadatas, md)
	}

	return metadatas, nil
}

// RenameWallet implements the Driver interface.
func (lwd *LedgerWalletDriver) RenameWallet(newName []byte, id []byte, pw []byte) error {
	return errNotSupported
}

// Init implements the wallet interface.
func (lw *LedgerWallet) Init(pw []byte) error {
	return nil
}

// CheckPassword implements the Wallet interface.
func (lw *LedgerWallet) CheckPassword(pw []byte) error {
	return nil
}

// ExportMasterDerivationKey implements the Wallet interface.
func (lw *LedgerWallet) ExportMasterDerivationKey(pw []byte) (crypto.MasterDerivationKey, error) {
	return crypto.MasterDerivationKey{}, errNotSupported
}

// Metadata implements the Wallet interface.
func (lw *LedgerWallet) Metadata() (wallet.Metadata, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	info := lw.dev.USBInfo()
	return wallet.Metadata{
		ID:                    []byte(info.Path),
		Name:                  []byte(fmt.Sprintf("%s %s (serial %s)", info.Manufacturer, info.Product, info.Serial)),
		DriverName:            ledgerWalletDriverName,
		DriverVersion:         ledgerWalletDriverVersion,
		SupportedTransactions: ledgerWalletSupportedTxs,
	}, nil
}

// ListKeys implements the Wallet interface.
func (lw *LedgerWallet) ListKeys() ([]crypto.Digest, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	reply, err := lw.dev.Exchange([]byte{0x80, 0x03, 0x00, 0x00, 0x00})
	if err != nil {
		return nil, err
	}

	var addr crypto.Digest
	copy(addr[:], reply)
	return []crypto.Digest{addr}, nil
}

// ImportKey implements the Wallet interface.
func (lw *LedgerWallet) ImportKey(sk crypto.PrivateKey) (crypto.Digest, error) {
	return crypto.Digest{}, errNotSupported
}

// ExportKey implements the Wallet interface.
func (lw *LedgerWallet) ExportKey(pk crypto.Digest, pw []byte) (crypto.PrivateKey, error) {
	return crypto.PrivateKey{}, errNotSupported
}

// GenerateKey implements the Wallet interface.
func (lw *LedgerWallet) GenerateKey(displayMnemonic bool) (crypto.Digest, error) {
	return crypto.Digest{}, errNotSupported
}

// DeleteKey implements the Wallet interface.
func (lw *LedgerWallet) DeleteKey(pk crypto.Digest, pw []byte) error {
	return errNotSupported
}

// ImportMultisigAddr implements the Wallet interface.
func (lw *LedgerWallet) ImportMultisigAddr(version, threshold uint8, pks []crypto.PublicKey) (crypto.Digest, error) {
	return crypto.Digest{}, errNotSupported
}

// LookupMultisigPreimage implements the Wallet interface.
func (lw *LedgerWallet) LookupMultisigPreimage(crypto.Digest) (version, threshold uint8, pks []crypto.PublicKey, err error) {
	return 0, 0, nil, errNotSupported
}

// ListMultisigAddrs implements the Wallet interface.
func (lw *LedgerWallet) ListMultisigAddrs() (addrs []crypto.Digest, err error) {
	return nil, nil
}

// DeleteMultisigAddr implements the Wallet interface.
func (lw *LedgerWallet) DeleteMultisigAddr(addr crypto.Digest, pw []byte) error {
	return errNotSupported
}

// SignTransaction implements the Wallet interface.
func (lw *LedgerWallet) SignTransaction(tx transactions.Transaction, pw []byte) ([]byte, error) {
	sig, err := lw.signTransactionHelper(tx)
	if err != nil {
		return nil, err
	}

	return protocol.Encode(transactions.SignedTxn{
		Txn: tx,
		Sig: sig,
	}), nil
}

// MultisigSignTransaction implements the Wallet interface.
func (lw *LedgerWallet) MultisigSignTransaction(tx transactions.Transaction, pk crypto.PublicKey, partial crypto.MultisigSig, pw []byte) (crypto.MultisigSig, error) {
	isValidKey := false
	for i := 0; i < len(partial.Subsigs); i++ {
		subsig := &partial.Subsigs[i]
		if subsig.Key == pk {
			isValidKey = true
		}
	}

	if !isValidKey {
		return partial, errMsigWrongKey
	}

	sig, err := lw.signTransactionHelper(tx)
	if err != nil {
		return partial, err
	}

	for i := 0; i < len(partial.Subsigs); i++ {
		subsig := &partial.Subsigs[i]
		if subsig.Key == pk {
			subsig.Sig = sig
		}
	}

	return partial, nil
}

func uint64le(i uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], i)
	return buf[:]
}

func (lw *LedgerWallet) signTransactionHelper(tx transactions.Transaction) (sig crypto.Signature, err error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	var msg []byte
	msg = append(msg, 0x80)

	switch tx.Type {
	case protocol.PaymentTx:
		msg = append(msg, 0x04)
	case protocol.KeyRegistrationTx:
		msg = append(msg, 0x05)
	default:
		err = fmt.Errorf("transaction type %s not supported", tx.Type)
		return
	}

	if len(tx.Note) != 0 {
		err = fmt.Errorf("transaction notes not supported")
		return
	}

	msg = append(msg, tx.Sender[:]...)
	msg = append(msg, uint64le(tx.Fee.Raw)...)
	msg = append(msg, uint64le(uint64(tx.FirstValid))...)
	msg = append(msg, uint64le(uint64(tx.LastValid))...)

	var genbuf [32]byte
	if len(tx.GenesisID) > len(genbuf) {
		err = fmt.Errorf("genesis ID %s too long (%d)", tx.GenesisID, len(tx.GenesisID))
		return
	}

	copy(genbuf[:], []byte(tx.GenesisID))
	msg = append(msg, genbuf[:]...)
	msg = append(msg, tx.GenesisHash[:]...)

	switch tx.Type {
	case protocol.PaymentTx:
		msg = append(msg, tx.Receiver[:]...)
		msg = append(msg, uint64le(tx.Amount.Raw)...)
		msg = append(msg, tx.CloseRemainderTo[:]...)
	case protocol.KeyRegistrationTx:
		msg = append(msg, tx.VotePK[:]...)
		msg = append(msg, tx.SelectionPK[:]...)
	}

	reply, err := lw.dev.Exchange(msg)
	if err != nil {
		return
	}

	copy(sig[:], reply)
	return
}
