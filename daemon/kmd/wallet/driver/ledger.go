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

package driver

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/daemon/kmd/wallet"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

const (
	ledgerWalletDriverName    = "ledger"
	ledgerWalletDriverVersion = 1
	ledgerIDLen               = 16

	ledgerClass            = uint8(0x80)
	ledgerInsGetPublicKey  = uint8(0x03)
	ledgerInsSignPaymentV2 = uint8(0x04)
	ledgerInsSignKeyregV2  = uint8(0x05)
	ledgerInsSignMsgpack   = uint8(0x08)
	ledgerP1first          = uint8(0x00)
	ledgerP1more           = uint8(0x80)
	ledgerP2last           = uint8(0x00)
	ledgerP2more           = uint8(0x80)
)

var ledgerWalletSupportedTxs = []protocol.TxType{protocol.PaymentTx, protocol.KeyRegistrationTx}

// LedgerWalletDriver provides access to a hardware wallet on the
// Ledger Nano S device.  The device must run the Algorand wallet
// application from https://github.com/algorand/ledger-app-algorand
type LedgerWalletDriver struct {
	mu      deadlock.Mutex
	wallets map[string]*LedgerWallet
	log     logging.Logger
	cfg     config.LedgerWalletDriverConfig
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
	lwd.mu.Lock()
	defer lwd.mu.Unlock()

	lw, ok := lwd.wallets[string(id)]
	if !ok {
		return nil, errWalletNotFound
	}

	return lw, nil
}

// scanWalletsLocked enumerates attached ledger devices and stores them.
// lwd.mu must be held
func (lwd *LedgerWalletDriver) scanWalletsLocked() error {

	if os.Getenv("KMD_NOUSB") != "" {
		return nil
	}

	// Initialize wallets map
	if lwd.wallets == nil {
		lwd.wallets = make(map[string]*LedgerWallet)
	}

	if lwd.cfg.Disable {
		return nil
	}

	// Enumerate attached wallet devices
	infos, err := LedgerEnumerate()
	if err != nil {
		return err
	}

	// Make map of existing device paths. We will pop each one that we
	// are able to scan for, meaning anything left over is dead, and we
	// should remove it
	curPaths := make(map[string]bool)
	for k := range lwd.wallets {
		curPaths[k] = true
	}

	// Try to open each new device, skipping ones that are already open.
	var newDevs []LedgerUSB
	for _, info := range infos {
		walletID := pathToID(info.Path)
		if curPaths[walletID] {
			delete(curPaths, walletID)
			continue
		}

		dev, err1 := info.Open()
		if err1 != nil {
			lwd.log.Warnf("enumerated but failed to open ledger %s %x: %v", info.Path, info.ProductID, err1)
			continue
		}

		newDevs = append(newDevs, LedgerUSB{
			hiddev: dev,
			info:   info,
		})
	}

	// Anything left in curPaths is no longer scanning. Close and remove
	for deadPath := range curPaths {
		err = lwd.wallets[deadPath].dev.hiddev.Close()
		if err != nil {
			lwd.log.Warnf("failed to close '%s': %v", deadPath, err)
		}
		delete(lwd.wallets, deadPath)
	}

	// Add in new ledger wallets if they appear valid
	for _, dev := range newDevs {
		newWallet := &LedgerWallet{
			dev: dev,
		}

		// Check that device responds to Algorand app requests
		_, err := newWallet.ListKeys()
		if err != nil {
			continue
		}

		id := pathToID(dev.USBInfo().Path)
		lwd.wallets[id] = newWallet
	}

	return nil
}

// InitWithConfig accepts a driver configuration.  Currently, the Ledger
// driver does not have any configuration parameters.  However, we use
// this to enumerate the USB devices.
func (lwd *LedgerWalletDriver) InitWithConfig(cfg config.KMDConfig, log logging.Logger) error {
	lwd.mu.Lock()
	defer lwd.mu.Unlock()

	lwd.log = log
	lwd.cfg = cfg.DriverConfig.LedgerWalletDriverConfig

	return lwd.scanWalletsLocked()
}

// ListWalletMetadatas returns all wallets supported by this driver.
func (lwd *LedgerWalletDriver) ListWalletMetadatas() (metadatas []wallet.Metadata, err error) {
	lwd.mu.Lock()
	defer lwd.mu.Unlock()

	err = lwd.scanWalletsLocked()
	if err != nil {
		return
	}

	for _, w := range lwd.wallets {
		md, err := w.Metadata()
		if err != nil {
			return nil, err
		}

		metadatas = append(metadatas, md)
	}

	metaSort := func(i, j int) bool {
		return bytes.Compare(metadatas[i].ID, metadatas[j].ID) < 0
	}

	// Sort metadatas by ID
	sort.Slice(metadatas, metaSort)

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

func pathToID(path string) string {
	// The Path USB info field is platform-dependent and sometimes
	// very long. We hash it to make the wallet name/ID less unwieldy
	pathHashFull := sha512.Sum512_256([]byte(path))
	return fmt.Sprintf("%x", pathHashFull[:ledgerIDLen])
}

// Metadata implements the Wallet interface.
func (lw *LedgerWallet) Metadata() (wallet.Metadata, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	info := lw.dev.USBInfo()

	walletID := pathToID(info.Path)
	walletName := fmt.Sprintf("%s-%s-%s-%s", info.Manufacturer, info.Product, info.Serial, walletID)
	walletName = strings.Replace(walletName, " ", "-", -1)

	return wallet.Metadata{
		ID:                    []byte(walletID),
		Name:                  []byte(walletName),
		DriverName:            ledgerWalletDriverName,
		DriverVersion:         ledgerWalletDriverVersion,
		SupportedTransactions: ledgerWalletSupportedTxs,
	}, nil
}

// ListKeys implements the Wallet interface.
func (lw *LedgerWallet) ListKeys() ([]crypto.Digest, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	reply, err := lw.dev.Exchange([]byte{ledgerClass, ledgerInsGetPublicKey, 0x00, 0x00, 0x00})
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
func (lw *LedgerWallet) SignTransaction(tx transactions.Transaction, pk crypto.PublicKey, pw []byte) ([]byte, error) {
	pks, err := lw.ListKeys()
	if err != nil {
		return nil, err
	}
	// Right now the device only supports one key
	if len(pks) > 1 {
		return nil, errors.New("LedgerWallet device only supports one key but ListKeys returned more than one")
	}
	if len(pks) < 1 {
		return nil, errKeyNotFound
	}
	if (pk != crypto.PublicKey{}) && pk != crypto.PublicKey(pks[0]) {
		// A specific key was requested; return an error if it's not the one on the device.
		return nil, errKeyNotFound
	}
	pk = crypto.PublicKey(pks[0])

	sig, err := lw.signTransactionHelper(tx)
	if err != nil {
		return nil, err
	}

	stxn := transactions.SignedTxn{
		Txn: tx,
		Sig: sig,
	}

	// Set the AuthAddr if the key we signed with doesn't match the txn sender
	if basics.Address(pk) != tx.Sender {
		stxn.AuthAddr = basics.Address(pk)
	}

	return protocol.Encode(&stxn), nil
}

// SignProgram implements the Wallet interface.
func (lw *LedgerWallet) SignProgram(data []byte, src crypto.Digest, pw []byte) ([]byte, error) {
	sig, err := lw.signProgramHelper(data)
	if err != nil {
		return nil, err
	}

	return sig[:], nil
}

// MultisigSignTransaction implements the Wallet interface.
func (lw *LedgerWallet) MultisigSignTransaction(tx transactions.Transaction, pk crypto.PublicKey, partial crypto.MultisigSig, pw []byte, signer crypto.Digest) (crypto.MultisigSig, error) {
	isValidKey := false
	for i := 0; i < len(partial.Subsigs); i++ {
		subsig := &partial.Subsigs[i]
		if subsig.Key == pk {
			isValidKey = true
			break
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

// MultisigSignProgram implements the Wallet interface.
func (lw *LedgerWallet) MultisigSignProgram(data []byte, src crypto.Digest, pk crypto.PublicKey, partial crypto.MultisigSig, pw []byte, useLegacyMsig bool) (crypto.MultisigSig, error) {
	isValidKey := false
	for i := 0; i < len(partial.Subsigs); i++ {
		subsig := &partial.Subsigs[i]
		if subsig.Key == pk {
			isValidKey = true
			break
		}
	}

	if !isValidKey {
		return partial, errMsigWrongKey
	}

	sig, err := lw.signProgramHelper(data)
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

	sig, err = lw.sendTransactionMsgpack(tx)
	if err == nil {
		return
	}

	ledgerErr, ok := err.(LedgerUSBError)
	if ok && ledgerErr == 0x6d00 {
		// We tried to send a msgpack-encoded transaction to the device,
		// but it doesn't support the new-style opcode, so fall back
		// to old-style encoding.
		sig, err = lw.sendTransactionOldStyle(tx)
	}

	return
}

func (lw *LedgerWallet) sendTransactionMsgpack(tx transactions.Transaction) (sig crypto.Signature, err error) {
	var reply []byte

	tosend := protocol.Encode(&tx)
	p1 := ledgerP1first
	p2 := ledgerP2more

	// As a precaution, make sure that chunk + 5-byte APDU header
	// fits in 8-bit length fields.
	const chunkSize = 250

	for p2 != ledgerP2last {
		var chunk []byte
		if len(tosend) > chunkSize {
			chunk = tosend[:chunkSize]
		} else {
			chunk = tosend
			p2 = ledgerP2last
		}

		var msg []byte
		msg = append(msg, ledgerClass, ledgerInsSignMsgpack, p1, p2, uint8(len(chunk)))
		msg = append(msg, chunk...)

		reply, err = lw.dev.Exchange(msg)
		if err != nil {
			return
		}

		tosend = tosend[len(chunk):]
		p1 = ledgerP1more
	}

	if len(reply) > len(sig) {
		// Error related to transaction decoding.
		errmsg := string(reply[len(sig)+1:])
		err = errors.New(errmsg)
		return
	}

	copy(sig[:], reply)
	return
}

func (lw *LedgerWallet) sendTransactionOldStyle(tx transactions.Transaction) (sig crypto.Signature, err error) {
	var msg []byte
	msg = append(msg, ledgerClass)

	switch tx.Type {
	case protocol.PaymentTx:
		msg = append(msg, ledgerInsSignPaymentV2)
	case protocol.KeyRegistrationTx:
		msg = append(msg, ledgerInsSignKeyregV2)
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

func (lw *LedgerWallet) signProgramHelper(data []byte) (sig crypto.Signature, err error) {
	// TODO: extend client side code for signing program
	err = errors.New("signing programs not yet implemented for ledger wallet")
	return
}
