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

package txnsync

import (
	"bytes"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

const maxEncodedTransactionGroup = 30000
const maxEncodedTransactionGroupEntries = 30000
const maxBitmaskSize = (maxEncodedTransactionGroupEntries+7)/8 + 1
const signatureSize = 64
const maxSignatureBytes = maxEncodedTransactionGroupEntries * signatureSize
const addressSize = 32
const maxAddressBytes = maxEncodedTransactionGroupEntries * addressSize

var errDataMissing = fmt.Errorf("failed to decode: data missing")

//msgp:allocbound txnGroups maxEncodedTransactionGroupEntries
type txnGroups []transactions.SignedTxn

type txGroupsEncodingStub struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	TotalTransactionsCount uint64 `codec:"ttc"`
	TransactionGroupCount  uint64 `codec:"tgc"`
	TransactionGroupSizes  []byte `codec:"tgs,allocbound=maxEncodedTransactionGroup"`

	SignedTxns []transactions.SignedTxn `codec:"st,allocbound=maxEncodedTransactionGroup"`

	encodedSignedTxns

	TxnGroups []txnGroups `codec:"txng,allocbound=maxEncodedTransactionGroup"`
}

type encodedSignedTxns struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sig        []byte  `codec:"sig,allocbound=maxSignatureBytes"`
	BitmaskSig bitmask `codec:"sigbm"`

	encodedMsigs
	encodedLsigs

	AuthAddr        []byte  `codec:"sgnr,allocbound=maxAddressBytes"`
	BitmaskAuthAddr bitmask `codec:"sgnrbm"`

	encodedTxns
}

type encodedMsigs struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Version          []uint8 `codec:"msigv,allocbound=maxEncodedTransactionGroup"`
	BitmaskVersion   bitmask `codec:"msigvbm"`
	Threshold        []uint8 `codec:"msigthr,allocbound=maxEncodedTransactionGroup"`
	BitmaskThreshold bitmask `codec:"msigthrbm"`
	// splitting subsigs further make the code much more complicated / does not give gains
	Subsigs        [][]crypto.MultisigSubsig `codec:"subsig,allocbound=maxEncodedTransactionGroup,allocbound=crypto.MaxMultisig"`
	BitmaskSubsigs bitmask                   `codec:"subsigsbm"`
}

type encodedLsigs struct {
	_struct          struct{}   `codec:",omitempty,omitemptyarray"`
	Logic            [][]byte   `codec:"lsigl,allocbound=maxEncodedTransactionGroup,allocbound=config.MaxLogicSigMaxSize"`
	BitmaskLogic     bitmask    `codec:"lsiglbm"`
	LogicArgs        [][][]byte `codec:"lsigarg,allocbound=maxEncodedTransactionGroup,allocbound=transactions.EvalMaxArgs,allocbound=config.MaxLogicSigMaxSize"`
	BitmaskLogicArgs bitmask    `codec:"lsigargbm"`
}

type encodedTxns struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	TxType        []byte  `codec:"type,allocbound=maxEncodedTransactionGroup"`
	BitmaskTxType bitmask `codec:"typebm"`
	TxTypeOffset  byte    `codec:"typeo"`

	encodedTxnHeaders
	encodedKeyregTxnFields
	encodedPaymentTxnFields
	encodedAssetConfigTxnFields
	encodedAssetTransferTxnFields
	encodedAssetFreezeTxnFields
	encodedApplicationCallTxnFields
	encodedCompactCertTxnFields
}

type encodedTxnHeaders struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sender             []byte              `codec:"snd,allocbound=maxAddressBytes"`
	BitmaskSender      bitmask             `codec:"sndbm"`
	Fee                []basics.MicroAlgos `codec:"fee,allocbound=maxEncodedTransactionGroup"`
	BitmaskFee         bitmask             `codec:"feebm"`
	FirstValid         []basics.Round      `codec:"fv,allocbound=maxEncodedTransactionGroup"`
	BitmaskFirstValid  bitmask             `codec:"fvbm"`
	LastValid          []basics.Round      `codec:"lv,allocbound=maxEncodedTransactionGroup"`
	BitmaskLastValid   bitmask             `codec:"lvbm"`
	Note               [][]byte            `codec:"note,allocbound=maxEncodedTransactionGroup"` // TODO whats the correct allocbound?
	BitmaskNote        bitmask             `codec:"notebm"`
	GenesisID          string              `codec:"gen"`
	BitmaskGenesisID   bitmask             `codec:"genbm"`
	GenesisHash        crypto.Digest       `codec:"gh"`
	BitmaskGenesisHash bitmask             `codec:"ghbm"`

	BitmaskGroup bitmask `codec:"grpbm"`

	Lease        []byte  `codec:"lx,allocbound=maxAddressBytes"`
	BitmaskLease bitmask `codec:"lxbm"`

	RekeyTo        []byte  `codec:"rekey,allocbound=maxAddressBytes"`
	BitmaskRekeyTo bitmask `codec:"rekeybm"`
}

type encodedKeyregTxnFields struct {
	_struct                 struct{}       `codec:",omitempty,omitemptyarray"`
	VotePK                  []byte         `codec:"votekey,allocbound=maxAddressBytes"`
	SelectionPK             []byte         `codec:"selkey,allocbound=maxAddressBytes"`
	VoteFirst               []basics.Round `codec:"votefst,allocbound=maxEncodedTransactionGroup"`
	BitmaskVoteFirst        bitmask        `codec:"votefstbm"`
	VoteLast                []basics.Round `codec:"votelst,allocbound=maxEncodedTransactionGroup"`
	BitmaskVoteLast         bitmask        `codec:"votelstbm"`
	VoteKeyDilution         []uint64       `codec:"votekd,allocbound=maxEncodedTransactionGroup"`
	BitmaskKeys             bitmask        `codec:"votekbm"`
	BitmaskNonparticipation bitmask        `codec:"nonpartbm"`
}

type encodedPaymentTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Receiver        []byte              `codec:"rcv,allocbound=maxAddressBytes"`
	BitmaskReceiver bitmask             `codec:"rcvbm"`
	Amount          []basics.MicroAlgos `codec:"amt,allocbound=maxEncodedTransactionGroup"`
	BitmaskAmount   bitmask             `codec:"amtbm"`

	CloseRemainderTo        []byte  `codec:"close,allocbound=maxAddressBytes"`
	BitmaskCloseRemainderTo bitmask `codec:"closebm"`
}

type encodedAssetConfigTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	ConfigAsset        []basics.AssetIndex `codec:"caid,allocbound=maxEncodedTransactionGroup"`
	BitmaskConfigAsset bitmask             `codec:"caidbm"`

	encodedAssetParams
}

type encodedAssetParams struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Total        []uint64 `codec:"t,allocbound=maxEncodedTransactionGroup"`
	BitmaskTotal bitmask  `codec:"tbm"`

	Decimals        []uint32 `codec:"dc,allocbound=maxEncodedTransactionGroup"`
	BitmaskDecimals bitmask  `codec:"dcbm"`

	BitmaskDefaultFrozen bitmask `codec:"dfbm"`

	UnitName        []string `codec:"un,allocbound=maxEncodedTransactionGroup"`
	BitmaskUnitName bitmask  `codec:"unbm"`

	AssetName        []string `codec:"an,allocbound=maxEncodedTransactionGroup"`
	BitmaskAssetName bitmask  `codec:"anbm"`

	URL        []string `codec:"au,allocbound=maxEncodedTransactionGroup"`
	BitmaskURL bitmask  `codec:"aubm"`

	MetadataHash        []byte  `codec:"am,allocbound=maxAddressBytes"`
	BitmaskMetadataHash bitmask `codec:"ambm"`

	Manager        []byte  `codec:"m,allocbound=maxAddressBytes"`
	BitmaskManager bitmask `codec:"mbm"`

	Reserve        []byte  `codec:"r,allocbound=maxAddressBytes"`
	BitmaskReserve bitmask `codec:"rbm"`

	Freeze        []byte  `codec:"f,allocbound=maxAddressBytes"`
	BitmaskFreeze bitmask `codec:"fbm"`

	Clawback        []byte  `codec:"c,allocbound=maxAddressBytes"`
	BitmaskClawback bitmask `codec:"cbm"`
}

type encodedAssetTransferTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	XferAsset        []basics.AssetIndex `codec:"xaid,allocbound=maxEncodedTransactionGroup"`
	BitmaskXferAsset bitmask             `codec:"xaidbm"`

	AssetAmount        []uint64 `codec:"aamt,allocbound=maxEncodedTransactionGroup"`
	BitmaskAssetAmount bitmask  `codec:"aamtbm"`

	AssetSender        []byte  `codec:"asnd,allocbound=maxAddressBytes"`
	BitmaskAssetSender bitmask `codec:"asndbm"`

	AssetReceiver        []byte  `codec:"arcv,allocbound=maxAddressBytes"`
	BitmaskAssetReceiver bitmask `codec:"arcvbm"`

	AssetCloseTo        []byte  `codec:"aclose,allocbound=maxAddressBytes"`
	BitmaskAssetCloseTo bitmask `codec:"aclosebm"`
}

type encodedAssetFreezeTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	FreezeAccount        []byte  `codec:"fadd,allocbound=maxAddressBytes"`
	BitmaskFreezeAccount bitmask `codec:"faddbm"`

	FreezeAsset        []basics.AssetIndex `codec:"faid,allocbound=maxEncodedTransactionGroup"`
	BitmaskFreezeAsset bitmask             `codec:"faidbm"`

	BitmaskAssetFrozen bitmask `codec:"afrzbm"`
}

//msgp:allocbound applicationArgs transactions.EncodedMaxApplicationArgs
type applicationArgs [][]byte

//msgp:allocbound addresses transactions.EncodedMaxAccounts
type addresses []basics.Address

//msgp:allocbound appIndices transactions.EncodedMaxForeignApps
type appIndices []basics.AppIndex

//msgp:allocbound assetIndices transactions.EncodedMaxForeignAssets
type assetIndices []basics.AssetIndex

//msgp:allocbound program config.MaxAppProgramLen
type program []byte

type encodedApplicationCallTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	ApplicationID        []basics.AppIndex `codec:"apid,allocbound=maxEncodedTransactionGroup"`
	BitmaskApplicationID bitmask           `codec:"apidbm"`

	OnCompletion        []byte  `codec:"apan,allocbound=maxEncodedTransactionGroup"`
	BitmaskOnCompletion bitmask `codec:"apanbm"`

	ApplicationArgs        []applicationArgs `codec:"apaa,allocbound=maxEncodedTransactionGroup"`
	BitmaskApplicationArgs bitmask           `codec:"apaabm"`

	Accounts        []addresses `codec:"apat,allocbound=maxEncodedTransactionGroup"`
	BitmaskAccounts bitmask     `codec:"apatbm"`

	ForeignApps        []appIndices `codec:"apfa,allocbound=maxEncodedTransactionGroup"`
	BitmaskForeignApps bitmask      `codec:"apfabm"`

	ForeignAssets        []assetIndices `codec:"apas,allocbound=maxEncodedTransactionGroup"`
	BitmaskForeignAssets bitmask        `codec:"apasbm"`

	LocalNumUint             []uint64 `codec:"lnui,allocbound=maxEncodedTransactionGroup"`
	BitmaskLocalNumUint      bitmask  `codec:"lnuibm"`
	LocalNumByteSlice        []uint64 `codec:"lnbs,allocbound=maxEncodedTransactionGroup"`
	BitmaskLocalNumByteSlice bitmask  `codec:"lnbsbm"`

	GlobalNumUint             []uint64 `codec:"gnui,allocbound=maxEncodedTransactionGroup"`
	BitmaskGlobalNumUint      bitmask  `codec:"gnuibm"`
	GlobalNumByteSlice        []uint64 `codec:"gnbs,allocbound=maxEncodedTransactionGroup"`
	BitmaskGlobalNumByteSlice bitmask  `codec:"gnbsbm"`

	ApprovalProgram        []program `codec:"apap,allocbound=maxEncodedTransactionGroup"`
	BitmaskApprovalProgram bitmask   `codec:"apapbm"`

	ClearStateProgram        []program `codec:"apsu,allocbound=maxEncodedTransactionGroup"`
	BitmaskClearStateProgram bitmask   `codec:"apsubm"`
}

type encodedCompactCertTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	CertRound        []basics.Round `codec:"certrnd,allocbound=maxEncodedTransactionGroup"`
	BitmaskCertRound bitmask        `codec:"certrndbm"`

	CertType        []protocol.CompactCertType `codec:"certtype,allocbound=maxEncodedTransactionGroup"`
	BitmaskCertType bitmask                    `codec:"certtypebm"`

	//Cert        []compactcert.Cert `codec:"cert,allocbound=maxEncodedTransactionGroup"`
	//BitmaskCert bitmask            `codec:"certbm"`
	encodedCert
}

//msgp:allocbound certProofs compactcert.MaxProofDigests
type certProofs []crypto.Digest

//msgp:allocbound revealMap compactcert.MaxReveals
type revealMap map[uint64]compactcert.Reveal

// SortUint64 implements sorting by uint64 keys for
// canonical encoding of maps in msgpack format.
type SortUint64 = compactcert.SortUint64

type encodedCert struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SigCommit        []byte  `codec:"certc,allocbound=maxAddressBytes"`
	BitmaskSigCommit bitmask `codec:"certcbm"`

	SignedWeight        []uint64 `codec:"certw,allocbound=maxEncodedTransactionGroup"`
	BitmaskSignedWeight bitmask  `codec:"certwbm"`

	SigProofs        []certProofs `codec:"certS,allocbound=maxEncodedTransactionGroup"`
	BitmaskSigProofs bitmask      `codec:"certSbm"`

	PartProofs        []certProofs `codec:"certP,allocbound=maxEncodedTransactionGroup"`
	BitmaskPartProofs bitmask      `codec:"certPbm"`

	Reveals        []revealMap `codec:"certr,allocbound=maxEncodedTransactionGroup"`
	BitmaskReveals bitmask     `codec:"certrbm"`
}

const (
	paymentTx = iota
	keyRegistrationTx
	assetConfigTx
	assetTransferTx
	assetFreezeTx
	applicationCallTx
	compactCertTx
	unknownTx
)

// TxTypeToByte converts a TxType to byte encoding
func TxTypeToByte(t protocol.TxType) byte {
	switch t {
	case protocol.PaymentTx:
		return paymentTx
	case protocol.KeyRegistrationTx:
		return keyRegistrationTx
	case protocol.AssetConfigTx:
		return assetConfigTx
	case protocol.AssetTransferTx:
		return assetTransferTx
	case protocol.AssetFreezeTx:
		return assetFreezeTx
	case protocol.ApplicationCallTx:
		return applicationCallTx
	case protocol.CompactCertTx:
		return compactCertTx
	default:
		logging.Base().Errorf("invalid txtype") // TODO: (nguo) perform proper error handling here instead
		return unknownTx
	}
}

// ByteToTxType converts a byte encoding to TxType
func ByteToTxType(b byte) protocol.TxType {
	if int(b) >= len(protocol.TxnTypes) {
		return protocol.UnknownTx
	}
	return protocol.TxnTypes[b]
}

//msgp:allocbound bitmask maxBitmaskSize
type bitmask []byte

// assumed to be in mode 0, sets bit at index to 1
func (b bitmask) SetBit(index int) {
	byteIndex := index/8 + 1
	b[byteIndex] ^= 1 << (index % 8)
}

func (b bitmask) EntryExists(index int) bool {
	byteIndex := index/8 + 1
	return byteIndex < len(b) && (b[byteIndex]&(1<<(index%8)) != 0)
}

func (b *bitmask) trimBitmask(entries int) {
	if *b == nil {
		return
	}
	lastExists := 0
	lastNotExists := 0
	numExists := 0
	for i := 0; i < entries; i++ {
		byteIndex := i/8 + 1
		if (*b)[byteIndex]&(1<<(i%8)) != 0 {
			lastExists = i
			numExists++
		} else {
			lastNotExists = i
		}
	}
	bitmaskType := 0
	bestSize := bytesNeededBitmask(lastExists)
	if bestSize > bytesNeededBitmask(lastNotExists) {
		bitmaskType = 1
		bestSize = bytesNeededBitmask(lastNotExists)
	}
	if bestSize > numExists*2+1 {
		bitmaskType = 2
		bestSize = numExists*2 + 1
	}
	if bestSize > (entries-numExists)*2+1 {
		bitmaskType = 3
		bestSize = (entries-numExists)*2 + 1
	}
	switch bitmaskType {
	case 1:
		(*b)[0] = 1
		for i := range *b {
			if i != 0 {
				(*b)[i] = 255 - (*b)[i] // invert bits
			}
		}
	case 2:
		newBitmask := make(bitmask, 1, bestSize)
		newBitmask[0] = 2
		last := 0
		for i := 0; i < entries; i++ {
			byteIndex := i/8 + 1
			if (*b)[byteIndex]&(1<<(i%8)) != 0 {
				diff := i - last
				newBitmask = append(newBitmask, byte(diff/256), byte(diff%256))
				last = i
			}
		}
		*b = newBitmask
		return
	case 3:
		newBitmask := make(bitmask, 1, bestSize)
		newBitmask[0] = 3
		last := 0
		for i := 0; i < entries; i++ {
			byteIndex := i/8 + 1
			if (*b)[byteIndex]&(1<<(i%8)) == 0 {
				diff := i - last
				newBitmask = append(newBitmask, byte(diff/256), byte(diff%256))
				last = i
			}
		}
		*b = newBitmask
		return
	default:
	}

	*b = bytes.TrimRight(*b, string(0))
}

func (b *bitmask) expandBitmask(entries int) {
	option := 0
	if len(*b) > 0 {
		option = int((*b)[0])
	} else {
		return
	}
	switch option {
	case 0: // if we have the bit 1 then we have an entry at the corresponding bit index.
		return
	case 1: // if we have the bit 0 then we have an entry at the corresponding bit index.
		newBitmask := make(bitmask, bytesNeededBitmask(entries))
		for i := range newBitmask {
			if i != 0 {
				if i < len(*b) {
					newBitmask[i] = 255 - (*b)[i] // invert bits
				} else {
					newBitmask[i] = 255
				}
			}
		}
		*b = newBitmask
	case 2: // contains a list of bytes designating the transaction bit index
		newBitmask := make(bitmask, bytesNeededBitmask(entries))
		sum := 0
		for i := 0; i*2+2 < len(*b); i++ {
			sum += int((*b)[i*2+1])*256 + int((*b)[i*2+2])
			newBitmask.SetBit(sum)
		}
		*b = newBitmask
	case 3: // contain a list of bytes designating the negative transaction bit index
		newBitmask := make(bitmask, bytesNeededBitmask(entries))
		sum := 0
		for i := 0; i*2+2 < len(*b); i++ {
			sum += int((*b)[i*2+1])*256 + int((*b)[i*2+2])
			newBitmask.SetBit(sum)
		}
		*b = newBitmask
		for i := range *b {
			if i != 0 {
				(*b)[i] = 255 - (*b)[i] // invert bits
			}
		}
	}
}

func bytesNeededBitmask(elements int) int {
	return (elements+7)/8 + 1
}

func getSlice(b []byte, index int, size int) ([]byte, error) {
	if index*size+size > len(b) {
		return nil, errDataMissing
	}
	return b[index*size : index*size+size], nil
}

func getNibble(b []byte, index int) (byte, error) {
	if index > len(b)*2 {
		return 0, errDataMissing
	}
	if index%2 == 0 {
		return b[index/2] / 16, nil
	}
	return b[index/2] % 16, nil
}

func squeezeByteArray(b []byte) []byte {
	if len(b)%2 == 1 {
		b = append(b, byte(0))
	}
	for index := 0; index*2 < len(b); index++ {
		b[index] = b[index*2]*16 + b[index*2+1]
	}
	return b[0 : len(b)/2]
}

func encodeTransactionGroupsOld(inTxnGroups []transactions.SignedTxGroup) []byte {
	stub := txGroupsEncodingStub{
		TxnGroups: make([]txnGroups, len(inTxnGroups)),
	}
	for i := range inTxnGroups {
		stub.TxnGroups[i] = inTxnGroups[i].Transactions
	}

	return stub.MarshalMsg(protocol.GetEncodingBuf()[:0])
}

func decodeTransactionGroupsOld(bytes []byte) (txnGroups []transactions.SignedTxGroup, err error) {
	if len(bytes) == 0 {
		return nil, nil
	}
	var stub txGroupsEncodingStub
	_, err = stub.UnmarshalMsg(bytes)
	if err != nil {
		return nil, err
	}
	txnGroups = make([]transactions.SignedTxGroup, len(stub.TxnGroups))
	for i := range stub.TxnGroups {
		txnGroups[i].Transactions = stub.TxnGroups[i]
	}
	return txnGroups, nil
}

func encodeTransactionGroups(inTxnGroups []transactions.SignedTxGroup) []byte {
	txnCount := 0
	for _, txGroup := range inTxnGroups {
		txnCount += len(txGroup.Transactions)
	}
	stub := txGroupsEncodingStub{
		TotalTransactionsCount: uint64(txnCount),
		TransactionGroupCount:  uint64(len(inTxnGroups)),
		TransactionGroupSizes:  make([]byte, 0, len(inTxnGroups)), // TODO compress this later to use 2 per byte
	}

	index := 0
	for _, txGroup := range inTxnGroups {
		if len(txGroup.Transactions) > 1 {
			for _, txn := range txGroup.Transactions {
				deconstructSignedTransactions(&stub, index, txn)
				index++
			}
			stub.TransactionGroupSizes = append(stub.TransactionGroupSizes, byte(len(txGroup.Transactions)-1))
		}
	}
	for _, txGroup := range inTxnGroups {
		if len(txGroup.Transactions) == 1 {
			for _, txn := range txGroup.Transactions {
				deconstructSignedTransactions(&stub, index, txn)
				index++
			}
		}
	}
	finishDeconstructSignedTransactions(&stub)

	return stub.MarshalMsg(protocol.GetEncodingBuf()[:0])
}

func decodeTransactionGroups(bytes []byte) (txnGroups []transactions.SignedTxGroup, err error) {
	if len(bytes) == 0 {
		return nil, nil
	}
	var stub txGroupsEncodingStub
	_, err = stub.UnmarshalMsg(bytes)
	if err != nil {
		return nil, err
	}

	stub.SignedTxns = make([]transactions.SignedTxn, stub.TotalTransactionsCount)

	err = reconstructSignedTransactions(&stub)
	if err != nil {
		return nil, err
	}

	txnGroups = make([]transactions.SignedTxGroup, stub.TransactionGroupCount)
	for txnCounter, txnGroupIndex := 0, 0; txnCounter < int(stub.TotalTransactionsCount); txnGroupIndex++ {
		size := 1
		if txnGroupIndex < len(stub.TransactionGroupSizes) {
			size = int(stub.TransactionGroupSizes[txnGroupIndex]) + 1
		}
		txnGroups[txnGroupIndex].Transactions = stub.SignedTxns[txnCounter : txnCounter+size]
		txnCounter += size
	}

	addGroupHashes(txnGroups, int(stub.TotalTransactionsCount), stub.BitmaskGroup)

	return txnGroups, nil
}

func addGroupHashes(txnGroups []transactions.SignedTxGroup, txnCount int, b bitmask) {
	index := 0
	txGroupHashes := make([]crypto.Digest, txnCount)
	for _, txns := range txnGroups {
		var txGroup transactions.TxGroup
		txGroup.TxGroupHashes = txGroupHashes[index : index+len(txns.Transactions)]
		for i, tx := range txns.Transactions {
			txGroup.TxGroupHashes[i] = crypto.HashObj(tx.Txn)
		}
		groupHash := crypto.HashObj(txGroup)
		b.expandBitmask(txnCount)
		for i := range txns.Transactions {
			if exists := b.EntryExists(index); exists {
				txns.Transactions[i].Txn.Group = groupHash
			}
			index++
		}
	}
}

// deconstructs SignedTxn's into lists of fields and bitmasks
func deconstructSignedTransactions(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Sig.MsgIsZero() {
		if stub.BitmaskSig == nil {
			stub.BitmaskSig = make(bitmask, bitmaskLen)
			stub.Sig = make([]byte, 0, int(stub.TotalTransactionsCount)*signatureSize)
		}
		stub.BitmaskSig.SetBit(i)
		stub.Sig = append(stub.Sig, txn.Sig[:]...)
	}
	deconstructMsigs(stub, i, txn)
	deconstructLsigs(stub, i, txn)
	if !txn.AuthAddr.MsgIsZero() {
		if stub.BitmaskAuthAddr == nil {
			stub.BitmaskAuthAddr = make(bitmask, bitmaskLen)
			stub.AuthAddr = make([]byte, 0, int(stub.TotalTransactionsCount)*addressSize)
		}
		stub.BitmaskAuthAddr.SetBit(i)
		stub.AuthAddr = append(stub.AuthAddr, txn.AuthAddr[:]...)
	}
	deconstructTransactions(stub, i, txn)
}

func finishDeconstructSignedTransactions(stub *txGroupsEncodingStub) {
	stub.BitmaskAuthAddr.trimBitmask(int(stub.TotalTransactionsCount))
	finishDeconstructMsigs(stub)
	finishDeconstructLsigs(stub)
	stub.BitmaskSig.trimBitmask(int(stub.TotalTransactionsCount))
	finishDeconstructTransactions(stub)
}

func deconstructMsigs(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if txn.Msig.Version != 0 {
		if stub.BitmaskVersion == nil {
			stub.BitmaskVersion = make(bitmask, bitmaskLen)
			stub.Version = make([]uint8, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskVersion.SetBit(i)
		stub.Version = append(stub.Version, txn.Msig.Version)
	}
	if txn.Msig.Threshold != 0 {
		if stub.BitmaskThreshold == nil {
			stub.BitmaskThreshold = make(bitmask, bitmaskLen)
			stub.Threshold = make([]uint8, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskThreshold.SetBit(i)
		stub.Threshold = append(stub.Threshold, txn.Msig.Threshold)
	}
	if txn.Msig.Subsigs != nil {
		if stub.BitmaskSubsigs == nil {
			stub.BitmaskSubsigs = make(bitmask, bitmaskLen)
			stub.Subsigs = make([][]crypto.MultisigSubsig, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskSubsigs.SetBit(i)
		stub.Subsigs = append(stub.Subsigs, txn.Msig.Subsigs)
	}
}

func finishDeconstructMsigs(stub *txGroupsEncodingStub) {
	stub.BitmaskVersion.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskThreshold.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskSubsigs.trimBitmask(int(stub.TotalTransactionsCount))
}

func deconstructLsigs(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if txn.Lsig.Logic != nil {
		if stub.BitmaskLogic == nil {
			stub.BitmaskLogic = make(bitmask, bitmaskLen)
			stub.Logic = make([][]byte, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskLogic.SetBit(i)
		stub.Logic = append(stub.Logic, txn.Lsig.Logic)
	}
	if txn.Lsig.Args != nil {
		if stub.BitmaskLogicArgs == nil {
			stub.BitmaskLogicArgs = make(bitmask, bitmaskLen)
			stub.LogicArgs = make([][][]byte, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskLogicArgs.SetBit(i)
		stub.LogicArgs = append(stub.LogicArgs, txn.Lsig.Args)
	}
	if !txn.Lsig.Sig.MsgIsZero() {
		if stub.BitmaskSig == nil {
			stub.BitmaskSig = make(bitmask, bitmaskLen)
			stub.Sig = make([]byte, 0, int(stub.TotalTransactionsCount)*signatureSize)
		}
		stub.BitmaskSig.SetBit(i)
		stub.Sig = append(stub.Sig, txn.Lsig.Sig[:]...)
	}
	if txn.Lsig.Msig.Version != 0 {
		if stub.BitmaskVersion == nil {
			stub.BitmaskVersion = make(bitmask, bitmaskLen)
			stub.Version = make([]uint8, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskVersion.SetBit(i)
		stub.Version = append(stub.Version, txn.Lsig.Msig.Version)
	}
	if txn.Lsig.Msig.Threshold != 0 {
		if stub.BitmaskThreshold == nil {
			stub.BitmaskThreshold = make(bitmask, bitmaskLen)
			stub.Threshold = make([]uint8, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskThreshold.SetBit(i)
		stub.Threshold = append(stub.Threshold, txn.Lsig.Msig.Threshold)
	}
	if txn.Lsig.Msig.Subsigs != nil {
		if stub.BitmaskSubsigs == nil {
			stub.BitmaskSubsigs = make(bitmask, bitmaskLen)
			stub.Subsigs = make([][]crypto.MultisigSubsig, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskSubsigs.SetBit(i)
		stub.Subsigs = append(stub.Subsigs, txn.Lsig.Msig.Subsigs)
	}
}

func finishDeconstructLsigs(stub *txGroupsEncodingStub) {
	stub.BitmaskLogic.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskLogicArgs.trimBitmask(int(stub.TotalTransactionsCount))
}

func deconstructTransactions(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	txTypeByte := TxTypeToByte(txn.Txn.Type)
	if txTypeByte != 0 {
		if stub.BitmaskTxType == nil {
			stub.BitmaskTxType = make(bitmask, bitmaskLen)
			stub.TxType = make([]byte, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskTxType.SetBit(i)
		stub.TxType = append(stub.TxType, txTypeByte)
	}
	deconstructTxnHeader(stub, i, txn)
	switch txn.Txn.Type {
	case protocol.PaymentTx:
		deconstructPaymentTxnFields(stub, i, txn)
	case protocol.KeyRegistrationTx:
		deconstructKeyregTxnFields(stub, i, txn)
	case protocol.AssetConfigTx:
		deconstructAssetConfigTxnFields(stub, i, txn)
	case protocol.AssetTransferTx:
		deconstructAssetTransferTxnFields(stub, i, txn)
	case protocol.AssetFreezeTx:
		deconstructAssetFreezeTxnFields(stub, i, txn)
	case protocol.ApplicationCallTx:
		deconstructApplicationCallTxnFields(stub, i, txn)
	case protocol.CompactCertTx:
		deconstructCompactCertTxnFields(stub, i, txn)
	}
}

func finishDeconstructTransactions(stub *txGroupsEncodingStub) {
	offset := byte(0)
	count := make(map[int]uint64)
	for _, t := range stub.TxType {
		count[int(t)]++
	}
	for i := range protocol.TxnTypes {
		if c, ok := count[i]; ok && c > stub.TotalTransactionsCount/2 {
			offset = byte(i)
		}
	}
	if offset != 0 {
		newTxTypes := make([]byte, 0, stub.TotalTransactionsCount)
		index := 0
		for i := 0; i < int(stub.TotalTransactionsCount); i++ {
			if exists := stub.BitmaskTxType.EntryExists(i); exists {
				if stub.TxType[index] == offset {
					stub.BitmaskTxType.SetBit(i)
				} else {
					newTxTypes = append(newTxTypes, stub.TxType[index])
				}
				index++
			} else {
				stub.BitmaskTxType.SetBit(i)
				newTxTypes = append(newTxTypes, offset)
			}
		}
		stub.TxType = newTxTypes
		stub.TxTypeOffset = offset
	}

	stub.BitmaskTxType.trimBitmask(int(stub.TotalTransactionsCount))
	stub.TxType = squeezeByteArray(stub.TxType)
	finishDeconstructTxnHeader(stub)
	finishDeconstructKeyregTxnFields(stub)
	finishDeconstructPaymentTxnFields(stub)
	finishDeconstructAssetConfigTxnFields(stub)
	finishDeconstructAssetTransferTxnFields(stub)
	finishDeconstructAssetFreezeTxnFields(stub)
	finishDeconstructApplicationCallTxnFields(stub)
	finishDeconstructCompactCertTxnFields(stub)
}

func deconstructTxnHeader(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.Sender.MsgIsZero() {
		if stub.BitmaskSender == nil {
			stub.BitmaskSender = make(bitmask, bitmaskLen)
			stub.Sender = make([]byte, 0, int(stub.TotalTransactionsCount)*addressSize)
		}
		stub.BitmaskSender.SetBit(i)
		stub.Sender = append(stub.Sender, txn.Txn.Sender[:]...)
	}
	if !txn.Txn.Fee.MsgIsZero() {
		if stub.BitmaskFee == nil {
			stub.BitmaskFee = make(bitmask, bitmaskLen)
			stub.Fee = make([]basics.MicroAlgos, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskFee.SetBit(i)
		stub.Fee = append(stub.Fee, txn.Txn.Fee)
	}
	if !txn.Txn.FirstValid.MsgIsZero() {
		if stub.BitmaskFirstValid == nil {
			stub.BitmaskFirstValid = make(bitmask, bitmaskLen)
			stub.FirstValid = make([]basics.Round, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskFirstValid.SetBit(i)
		stub.FirstValid = append(stub.FirstValid, txn.Txn.FirstValid)
	}
	if !txn.Txn.LastValid.MsgIsZero() {
		if stub.BitmaskLastValid == nil {
			stub.BitmaskLastValid = make(bitmask, bitmaskLen)
			stub.LastValid = make([]basics.Round, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskLastValid.SetBit(i)
		stub.LastValid = append(stub.LastValid, txn.Txn.LastValid)
	}
	if txn.Txn.Note != nil {
		if stub.BitmaskNote == nil {
			stub.BitmaskNote = make(bitmask, bitmaskLen)
			stub.Note = make([][]byte, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskNote.SetBit(i)
		stub.Note = append(stub.Note, txn.Txn.Note)
	}
	if txn.Txn.GenesisID != "" {
		if stub.BitmaskGenesisID == nil {
			stub.BitmaskGenesisID = make(bitmask, bitmaskLen)
		}
		stub.BitmaskGenesisID.SetBit(i)
		stub.GenesisID = txn.Txn.GenesisID
	}
	if !txn.Txn.GenesisHash.MsgIsZero() {
		if stub.BitmaskGenesisHash == nil {
			stub.BitmaskGenesisHash = make(bitmask, bitmaskLen)
		}
		stub.BitmaskGenesisHash.SetBit(i)
		stub.GenesisHash = txn.Txn.GenesisHash
	}
	if !txn.Txn.Group.MsgIsZero() {
		if stub.BitmaskGroup == nil {
			stub.BitmaskGroup = make(bitmask, bitmaskLen)
		}
		stub.BitmaskGroup.SetBit(i)
	}
	if txn.Txn.Lease != ([32]byte{}) {
		if stub.BitmaskLease == nil {
			stub.BitmaskLease = make(bitmask, bitmaskLen)
			stub.Lease = make([]byte, 0, int(stub.TotalTransactionsCount)*addressSize)
		}
		stub.BitmaskLease.SetBit(i)
		stub.Lease = append(stub.Lease, txn.Txn.Lease[:]...)
	}
	if !txn.Txn.RekeyTo.MsgIsZero() {
		if stub.BitmaskRekeyTo == nil {
			stub.BitmaskRekeyTo = make(bitmask, bitmaskLen)
			stub.RekeyTo = make([]byte, 0, int(stub.TotalTransactionsCount)*addressSize)
		}
		stub.BitmaskRekeyTo.SetBit(i)
		stub.RekeyTo = append(stub.RekeyTo, txn.Txn.RekeyTo[:]...)
	}
}

func finishDeconstructTxnHeader(stub *txGroupsEncodingStub) {
	stub.BitmaskSender.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskFee.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskFirstValid.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskLastValid.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskNote.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskGenesisID.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskGenesisHash.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskGroup.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskLease.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskRekeyTo.trimBitmask(int(stub.TotalTransactionsCount))
}

func deconstructKeyregTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.VotePK.MsgIsZero() || !txn.Txn.SelectionPK.MsgIsZero() || txn.Txn.VoteKeyDilution != 0 {
		if stub.BitmaskKeys == nil {
			stub.BitmaskKeys = make(bitmask, bitmaskLen)
			stub.VotePK = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
			stub.SelectionPK = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
			stub.VoteKeyDilution = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskKeys.SetBit(i)
		stub.VotePK = append(stub.VotePK, txn.Txn.VotePK[:]...)
		stub.SelectionPK = append(stub.SelectionPK, txn.Txn.SelectionPK[:]...)
		stub.VoteKeyDilution = append(stub.VoteKeyDilution, txn.Txn.VoteKeyDilution)
	}
	if !txn.Txn.VoteFirst.MsgIsZero() {
		if stub.BitmaskVoteFirst == nil {
			stub.BitmaskVoteFirst = make(bitmask, bitmaskLen)
			stub.VoteFirst = make([]basics.Round, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskVoteFirst.SetBit(i)
		stub.VoteFirst = append(stub.VoteFirst, txn.Txn.VoteFirst)
	}
	if !txn.Txn.VoteLast.MsgIsZero() {
		if stub.BitmaskVoteLast == nil {
			stub.BitmaskVoteLast = make(bitmask, bitmaskLen)
			stub.VoteLast = make([]basics.Round, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskVoteLast.SetBit(i)
		stub.VoteLast = append(stub.VoteLast, txn.Txn.VoteLast)
	}
	if txn.Txn.Nonparticipation {
		if stub.BitmaskNonparticipation == nil {
			stub.BitmaskNonparticipation = make(bitmask, bitmaskLen)
		}
		stub.BitmaskNonparticipation.SetBit(i)
	}
}

func finishDeconstructKeyregTxnFields(stub *txGroupsEncodingStub) {
	stub.BitmaskKeys.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskVoteFirst.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskVoteLast.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskNonparticipation.trimBitmask(int(stub.TotalTransactionsCount))
}

func deconstructPaymentTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.Receiver.MsgIsZero() {
		if stub.BitmaskReceiver == nil {
			stub.BitmaskReceiver = make(bitmask, bitmaskLen)
			stub.Receiver = make([]byte, 0, int(stub.TotalTransactionsCount)*addressSize)
		}
		stub.BitmaskReceiver.SetBit(i)
		stub.Receiver = append(stub.Receiver, txn.Txn.Receiver[:]...)
	}
	if !txn.Txn.Amount.MsgIsZero() {
		if stub.BitmaskAmount == nil {
			stub.BitmaskAmount = make(bitmask, bitmaskLen)
			stub.Amount = make([]basics.MicroAlgos, 0, int(stub.TotalTransactionsCount))
		}
		stub.BitmaskAmount.SetBit(i)
		stub.Amount = append(stub.Amount, txn.Txn.Amount)
	}
	if !txn.Txn.CloseRemainderTo.MsgIsZero() {
		if stub.BitmaskCloseRemainderTo == nil {
			stub.BitmaskCloseRemainderTo = make(bitmask, bitmaskLen)
			stub.CloseRemainderTo = make([]byte, 0, int(stub.TotalTransactionsCount)*addressSize)
		}
		stub.BitmaskCloseRemainderTo.SetBit(i)
		stub.CloseRemainderTo = append(stub.CloseRemainderTo, txn.Txn.CloseRemainderTo[:]...)
	}
}

func finishDeconstructPaymentTxnFields(stub *txGroupsEncodingStub) {
	stub.BitmaskReceiver.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAmount.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskCloseRemainderTo.trimBitmask(int(stub.TotalTransactionsCount))
}

func deconstructAssetConfigTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.ConfigAsset.MsgIsZero() {
		if stub.BitmaskConfigAsset == nil {
			stub.BitmaskConfigAsset = make(bitmask, bitmaskLen)
			stub.ConfigAsset = make([]basics.AssetIndex, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskConfigAsset.SetBit(i)
		stub.ConfigAsset = append(stub.ConfigAsset, txn.Txn.ConfigAsset)
	}
	deconstructAssetParams(stub, i, txn)
}

func finishDeconstructAssetConfigTxnFields(stub *txGroupsEncodingStub) {
	stub.BitmaskConfigAsset.trimBitmask(int(stub.TotalTransactionsCount))
	finishDeconstructAssetParams(stub)
}

func deconstructAssetParams(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if txn.Txn.AssetParams.Total != 0 {
		if stub.BitmaskTotal == nil {
			stub.BitmaskTotal = make(bitmask, bitmaskLen)
			stub.Total = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskTotal.SetBit(i)
		stub.Total = append(stub.Total, txn.Txn.AssetParams.Total)
	}
	if txn.Txn.AssetParams.Decimals != 0 {
		if stub.BitmaskDecimals == nil {
			stub.BitmaskDecimals = make(bitmask, bitmaskLen)
			stub.Decimals = make([]uint32, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskDecimals.SetBit(i)
		stub.Decimals = append(stub.Decimals, txn.Txn.AssetParams.Decimals)
	}
	if txn.Txn.AssetParams.DefaultFrozen {
		if stub.BitmaskDefaultFrozen == nil {
			stub.BitmaskDefaultFrozen = make(bitmask, bitmaskLen)
		}
		stub.BitmaskDefaultFrozen.SetBit(i)
	}
	if txn.Txn.AssetParams.UnitName != "" {
		if stub.BitmaskUnitName == nil {
			stub.BitmaskUnitName = make(bitmask, bitmaskLen)
			stub.UnitName = make([]string, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskUnitName.SetBit(i)
		stub.UnitName = append(stub.UnitName, txn.Txn.AssetParams.UnitName)
	}
	if txn.Txn.AssetParams.AssetName != "" {
		if stub.BitmaskAssetName == nil {
			stub.BitmaskAssetName = make(bitmask, bitmaskLen)
			stub.AssetName = make([]string, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskAssetName.SetBit(i)
		stub.AssetName = append(stub.AssetName, txn.Txn.AssetParams.AssetName)
	}
	if txn.Txn.AssetParams.URL != "" {
		if stub.BitmaskURL == nil {
			stub.BitmaskURL = make(bitmask, bitmaskLen)
			stub.URL = make([]string, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskURL.SetBit(i)
		stub.URL = append(stub.URL, txn.Txn.AssetParams.URL)
	}
	if txn.Txn.AssetParams.MetadataHash != [32]byte{} {
		if stub.BitmaskMetadataHash == nil {
			stub.BitmaskMetadataHash = make(bitmask, bitmaskLen)
			stub.MetadataHash = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
		}
		stub.BitmaskMetadataHash.SetBit(i)
		stub.MetadataHash = append(stub.MetadataHash, txn.Txn.AssetParams.MetadataHash[:]...)
	}
	if !txn.Txn.AssetParams.Manager.MsgIsZero() {
		if stub.BitmaskManager == nil {
			stub.BitmaskManager = make(bitmask, bitmaskLen)
			stub.Manager = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
		}
		stub.BitmaskManager.SetBit(i)
		stub.Manager = append(stub.Manager, txn.Txn.AssetParams.Manager[:]...)
	}
	if !txn.Txn.AssetParams.Reserve.MsgIsZero() {
		if stub.BitmaskReserve == nil {
			stub.BitmaskReserve = make(bitmask, bitmaskLen)
			stub.Reserve = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
		}
		stub.BitmaskReserve.SetBit(i)
		stub.Reserve = append(stub.Reserve, txn.Txn.AssetParams.Reserve[:]...)
	}
	if !txn.Txn.AssetParams.Freeze.MsgIsZero() {
		if stub.BitmaskFreeze == nil {
			stub.BitmaskFreeze = make(bitmask, bitmaskLen)
			stub.Freeze = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
		}
		stub.BitmaskFreeze.SetBit(i)
		stub.Freeze = append(stub.Freeze, txn.Txn.AssetParams.Freeze[:]...)
	}
	if !txn.Txn.AssetParams.Clawback.MsgIsZero() {
		if stub.BitmaskClawback == nil {
			stub.BitmaskClawback = make(bitmask, bitmaskLen)
			stub.Clawback = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
		}
		stub.BitmaskClawback.SetBit(i)
		stub.Clawback = append(stub.Clawback, txn.Txn.AssetParams.Clawback[:]...)
	}
}

func finishDeconstructAssetParams(stub *txGroupsEncodingStub) {
	stub.BitmaskTotal.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskDecimals.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskDefaultFrozen.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskUnitName.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetName.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskURL.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskMetadataHash.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskManager.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskReserve.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskFreeze.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskClawback.trimBitmask(int(stub.TotalTransactionsCount))
}

func deconstructAssetTransferTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.XferAsset.MsgIsZero() {
		if stub.BitmaskXferAsset == nil {
			stub.BitmaskXferAsset = make(bitmask, bitmaskLen)
			stub.XferAsset = make([]basics.AssetIndex, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskXferAsset.SetBit(i)
		stub.XferAsset = append(stub.XferAsset, txn.Txn.XferAsset)
	}
	if txn.Txn.AssetAmount != 0 {
		if stub.BitmaskAssetAmount == nil {
			stub.BitmaskAssetAmount = make(bitmask, bitmaskLen)
			stub.AssetAmount = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskAssetAmount.SetBit(i)
		stub.AssetAmount = append(stub.AssetAmount, txn.Txn.AssetAmount)
	}
	if !txn.Txn.AssetSender.MsgIsZero() {
		if stub.BitmaskAssetSender == nil {
			stub.BitmaskAssetSender = make(bitmask, bitmaskLen)
			stub.AssetSender = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
		}
		stub.BitmaskAssetSender.SetBit(i)
		stub.AssetSender = append(stub.AssetSender, txn.Txn.AssetSender[:]...)
	}
	if !txn.Txn.AssetReceiver.MsgIsZero() {
		if stub.BitmaskAssetReceiver == nil {
			stub.BitmaskAssetReceiver = make(bitmask, bitmaskLen)
			stub.AssetReceiver = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
		}
		stub.BitmaskAssetReceiver.SetBit(i)
		stub.AssetReceiver = append(stub.AssetReceiver, txn.Txn.AssetReceiver[:]...)
	}
	if !txn.Txn.AssetCloseTo.MsgIsZero() {
		if stub.BitmaskAssetCloseTo == nil {
			stub.BitmaskAssetCloseTo = make(bitmask, bitmaskLen)
			stub.AssetCloseTo = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
		}
		stub.BitmaskAssetCloseTo.SetBit(i)
		stub.AssetCloseTo = append(stub.AssetCloseTo, txn.Txn.AssetCloseTo[:]...)
	}
}

func finishDeconstructAssetTransferTxnFields(stub *txGroupsEncodingStub) {
	stub.BitmaskXferAsset.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetAmount.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetSender.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetReceiver.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetCloseTo.trimBitmask(int(stub.TotalTransactionsCount))
}

func deconstructAssetFreezeTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.FreezeAccount.MsgIsZero() {
		if stub.BitmaskFreezeAccount == nil {
			stub.BitmaskFreezeAccount = make(bitmask, bitmaskLen)
			stub.FreezeAccount = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
		}
		stub.BitmaskFreezeAccount.SetBit(i)
		stub.FreezeAccount = append(stub.FreezeAccount, txn.Txn.FreezeAccount[:]...)
	}
	if txn.Txn.FreezeAsset != 0 {
		if stub.BitmaskFreezeAsset == nil {
			stub.BitmaskFreezeAsset = make(bitmask, bitmaskLen)
			stub.FreezeAsset = make([]basics.AssetIndex, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskFreezeAsset.SetBit(i)
		stub.FreezeAsset = append(stub.FreezeAsset, txn.Txn.FreezeAsset)
	}
	if txn.Txn.AssetFrozen {
		if stub.BitmaskAssetFrozen == nil {
			stub.BitmaskAssetFrozen = make(bitmask, bitmaskLen)
		}
		stub.BitmaskAssetFrozen.SetBit(i)
	}
}

func finishDeconstructAssetFreezeTxnFields(stub *txGroupsEncodingStub) {
	stub.BitmaskFreezeAccount.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskFreezeAsset.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetFrozen.trimBitmask(int(stub.TotalTransactionsCount))
}

func deconstructApplicationCallTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.ApplicationID.MsgIsZero() {
		if stub.BitmaskApplicationID == nil {
			stub.BitmaskApplicationID = make(bitmask, bitmaskLen)
			stub.ApplicationID = make([]basics.AppIndex, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskApplicationID.SetBit(i)
		stub.ApplicationID = append(stub.ApplicationID, txn.Txn.ApplicationID)
	}
	if txn.Txn.OnCompletion != 0 {
		if stub.BitmaskOnCompletion == nil {
			stub.BitmaskOnCompletion = make(bitmask, bitmaskLen)
			stub.OnCompletion = make([]byte, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskOnCompletion.SetBit(i)
		stub.OnCompletion = append(stub.OnCompletion, byte(txn.Txn.OnCompletion))
	}
	if txn.Txn.ApplicationArgs != nil {
		if stub.BitmaskApplicationArgs == nil {
			stub.BitmaskApplicationArgs = make(bitmask, bitmaskLen)
			stub.ApplicationArgs = make([]applicationArgs, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskApplicationArgs.SetBit(i)
		stub.ApplicationArgs = append(stub.ApplicationArgs, txn.Txn.ApplicationArgs)
	}
	if txn.Txn.Accounts != nil {
		if stub.BitmaskAccounts == nil {
			stub.BitmaskAccounts = make(bitmask, bitmaskLen)
			stub.Accounts = make([]addresses, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskAccounts.SetBit(i)
		stub.Accounts = append(stub.Accounts, txn.Txn.Accounts)
	}
	if txn.Txn.ForeignApps != nil {
		if stub.BitmaskForeignApps == nil {
			stub.BitmaskForeignApps = make(bitmask, bitmaskLen)
			stub.ForeignApps = make([]appIndices, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskForeignApps.SetBit(i)
		stub.ForeignApps = append(stub.ForeignApps, txn.Txn.ForeignApps)
	}
	if txn.Txn.ForeignAssets != nil {
		if stub.BitmaskForeignAssets == nil {
			stub.BitmaskForeignAssets = make(bitmask, bitmaskLen)
			stub.ForeignAssets = make([]assetIndices, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskForeignAssets.SetBit(i)
		stub.ForeignAssets = append(stub.ForeignAssets, txn.Txn.ForeignAssets)
	}
	if !txn.Txn.LocalStateSchema.MsgIsZero() {
		if stub.BitmaskLocalNumUint == nil {
			stub.BitmaskLocalNumUint = make(bitmask, bitmaskLen)
			stub.LocalNumUint = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskLocalNumUint.SetBit(i)
		stub.LocalNumUint = append(stub.LocalNumUint, txn.Txn.LocalStateSchema.NumUint)
	}
	if !txn.Txn.LocalStateSchema.MsgIsZero() {
		if stub.BitmaskLocalNumByteSlice == nil {
			stub.BitmaskLocalNumByteSlice = make(bitmask, bitmaskLen)
			stub.LocalNumByteSlice = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskLocalNumByteSlice.SetBit(i)
		stub.LocalNumByteSlice = append(stub.LocalNumByteSlice, txn.Txn.LocalStateSchema.NumByteSlice)
	}
	if !txn.Txn.GlobalStateSchema.MsgIsZero() {
		if stub.BitmaskGlobalNumUint == nil {
			stub.BitmaskGlobalNumUint = make(bitmask, bitmaskLen)
			stub.GlobalNumUint = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskGlobalNumUint.SetBit(i)
		stub.GlobalNumUint = append(stub.GlobalNumUint, txn.Txn.GlobalStateSchema.NumUint)
	}
	if !txn.Txn.GlobalStateSchema.MsgIsZero() {
		if stub.BitmaskGlobalNumByteSlice == nil {
			stub.BitmaskGlobalNumByteSlice = make(bitmask, bitmaskLen)
			stub.GlobalNumByteSlice = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskGlobalNumByteSlice.SetBit(i)
		stub.GlobalNumByteSlice = append(stub.GlobalNumByteSlice, txn.Txn.GlobalStateSchema.NumByteSlice)
	}
	if txn.Txn.ApprovalProgram != nil {
		if stub.BitmaskApprovalProgram == nil {
			stub.BitmaskApprovalProgram = make(bitmask, bitmaskLen)
			stub.ApprovalProgram = make([]program, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskApprovalProgram.SetBit(i)
		stub.ApprovalProgram = append(stub.ApprovalProgram, txn.Txn.ApprovalProgram)
	}
	if txn.Txn.ClearStateProgram != nil {
		if stub.BitmaskClearStateProgram == nil {
			stub.BitmaskClearStateProgram = make(bitmask, bitmaskLen)
			stub.ClearStateProgram = make([]program, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskClearStateProgram.SetBit(i)
		stub.ClearStateProgram = append(stub.ClearStateProgram, txn.Txn.ClearStateProgram)
	}
}

func finishDeconstructApplicationCallTxnFields(stub *txGroupsEncodingStub) {
	stub.OnCompletion = squeezeByteArray(stub.OnCompletion)
	stub.BitmaskApplicationID.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskOnCompletion.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskApplicationArgs.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAccounts.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskForeignApps.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskForeignAssets.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskLocalNumUint.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskLocalNumByteSlice.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskGlobalNumUint.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskGlobalNumByteSlice.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskApprovalProgram.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskClearStateProgram.trimBitmask(int(stub.TotalTransactionsCount))
}

func deconstructCompactCertTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.CertRound.MsgIsZero() {
		if stub.BitmaskCertRound == nil {
			stub.BitmaskCertRound = make(bitmask, bitmaskLen)
			stub.CertRound = make([]basics.Round, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskCertRound.SetBit(i)
		stub.CertRound = append(stub.CertRound, txn.Txn.CertRound)
	}
	if txn.Txn.CertType != 0 {
		if stub.BitmaskCertType == nil {
			stub.BitmaskCertType = make(bitmask, bitmaskLen)
			stub.CertType = make([]protocol.CompactCertType, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskCertType.SetBit(i)
		stub.CertType = append(stub.CertType, txn.Txn.CertType)
	}
	deconstructCert(stub, i, txn)
}

func finishDeconstructCompactCertTxnFields(stub *txGroupsEncodingStub) {
	stub.BitmaskCertRound.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskCertType.trimBitmask(int(stub.TotalTransactionsCount))
	finishDeconstructCert(stub)
}

func deconstructCert(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	if !txn.Txn.Cert.SigCommit.MsgIsZero() {
		if stub.BitmaskSigCommit == nil {
			stub.BitmaskSigCommit = make(bitmask, bitmaskLen)
			stub.SigCommit = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
		}
		stub.BitmaskSigCommit.SetBit(i)
		stub.SigCommit = append(stub.SigCommit, txn.Txn.Cert.SigCommit[:]...)
	}
	if txn.Txn.Cert.SignedWeight != 0 {
		if stub.BitmaskSignedWeight == nil {
			stub.BitmaskSignedWeight = make(bitmask, bitmaskLen)
			stub.SignedWeight = make([]uint64, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskSignedWeight.SetBit(i)
		stub.SignedWeight = append(stub.SignedWeight, txn.Txn.Cert.SignedWeight)
	}
	if txn.Txn.Cert.SigProofs != nil {
		if stub.BitmaskSigProofs == nil {
			stub.BitmaskSigProofs = make(bitmask, bitmaskLen)
			stub.SigProofs = make([]certProofs, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskSigProofs.SetBit(i)
		stub.SigProofs = append(stub.SigProofs, txn.Txn.Cert.SigProofs)
	}
	if txn.Txn.Cert.PartProofs != nil {
		if stub.BitmaskPartProofs == nil {
			stub.BitmaskPartProofs = make(bitmask, bitmaskLen)
			stub.PartProofs = make([]certProofs, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskPartProofs.SetBit(i)
		stub.PartProofs = append(stub.PartProofs, txn.Txn.Cert.PartProofs)
	}
	if txn.Txn.Cert.Reveals != nil {
		if stub.BitmaskReveals == nil {
			stub.BitmaskReveals = make(bitmask, bitmaskLen)
			stub.Reveals = make([]revealMap, 0, stub.TotalTransactionsCount)
		}
		stub.BitmaskReveals.SetBit(i)
		stub.Reveals = append(stub.Reveals, txn.Txn.Cert.Reveals)
	}
}

func finishDeconstructCert(stub *txGroupsEncodingStub) {
	stub.BitmaskSigCommit.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskSignedWeight.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskSigProofs.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskPartProofs.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskReveals.trimBitmask(int(stub.TotalTransactionsCount))
}

func reconstructSignedTransactions(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskSig.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSig.EntryExists(i); exists {
			slice, err := getSlice(stub.Sig, index, signatureSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Sig[:], slice)
			index++
		}
	}
	if err := reconstructMsigs(stub); err != nil {
		return fmt.Errorf("failed to msigs: %v", err)
	}
	if err := reconstructLsigs(stub); err != nil {
		return fmt.Errorf("failed to lsigs: %v", err)
	}
	index = 0
	stub.BitmaskAuthAddr.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAuthAddr.EntryExists(i); exists {
			slice, err := getSlice(stub.AuthAddr, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].AuthAddr[:], slice)
			index++
		}
	}

	return reconstructTransactions(stub)
}

func reconstructMsigs(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskVersion.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskVersion.EntryExists(i); exists {
			if index >= len(stub.Version) {
				return errDataMissing
			}
			stub.SignedTxns[i].Msig.Version = stub.Version[index]
			index++
		}
	}
	index = 0
	stub.BitmaskThreshold.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskThreshold.EntryExists(i); exists {
			if index >= len(stub.Threshold) {
				return errDataMissing
			}
			stub.SignedTxns[i].Msig.Threshold = stub.Threshold[index]
			index++
		}
	}
	index = 0
	stub.BitmaskSubsigs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSubsigs.EntryExists(i); exists {
			if index >= len(stub.Subsigs) {
				return errDataMissing
			}
			stub.SignedTxns[i].Msig.Subsigs = stub.Subsigs[index]
			index++
		}
	}
	return nil
}

func reconstructLsigs(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskLogic.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLogic.EntryExists(i); exists {
			if index >= len(stub.Logic) {
				return errDataMissing
			}
			stub.SignedTxns[i].Lsig.Logic = stub.Logic[index]
			// fetch sig/msig
			stub.SignedTxns[i].Lsig.Sig = stub.SignedTxns[i].Sig
			stub.SignedTxns[i].Sig = crypto.Signature{}
			stub.SignedTxns[i].Lsig.Msig = stub.SignedTxns[i].Msig
			stub.SignedTxns[i].Msig = crypto.MultisigSig{}
			index++
		}
	}
	index = 0
	stub.BitmaskLogicArgs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLogicArgs.EntryExists(i); exists {
			if index >= len(stub.LogicArgs) {
				return errDataMissing
			}
			stub.SignedTxns[i].Lsig.Args = stub.LogicArgs[index]
			index++
		}
	}
	return nil
}

func reconstructTransactions(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskTxType.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskTxType.EntryExists(i); exists {
			b, err := getNibble(stub.TxType, index)
			if err != nil {
				return err
			}
			if b == stub.TxTypeOffset {
				stub.SignedTxns[i].Txn.Type = ByteToTxType(0)
			} else {
				stub.SignedTxns[i].Txn.Type = ByteToTxType(b)
			}
			index++
		} else {
			stub.SignedTxns[i].Txn.Type = ByteToTxType(stub.TxTypeOffset)
		}
	}

	if err := reconstructTxnHeader(stub); err != nil {
		return fmt.Errorf("failed to reconstructTxnHeader: %v", err)
	}
	if err := reconstructKeyregTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructKeyregTxnFields: %v", err)
	}
	if err := reconstructPaymentTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructPaymentTxnFields: %v", err)
	}
	if err := reconstructAssetConfigTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructAssetConfigTxnFields: %v", err)
	}
	if err := reconstructAssetTransferTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructAssetTransferTxnFields: %v", err)
	}
	if err := reconstructAssetFreezeTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructAssetFreezeTxnFields: %v", err)
	}
	if err := reconstructApplicationCallTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructApplicationCallTxnFields: %v", err)
	}
	if err := reconstructCompactCertTxnFields(stub); err != nil {
		return fmt.Errorf("failed to reconstructCompactCertTxnFields: %v", err)
	}
	return nil
}

func reconstructTxnHeader(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskSender.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSender.EntryExists(i); exists {
			slice, err := getSlice(stub.Sender, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.Sender[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskFee.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFee.EntryExists(i); exists {
			if index >= len(stub.Fee) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Fee = stub.Fee[index]
			index++
		}
	}
	index = 0
	stub.BitmaskFirstValid.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFirstValid.EntryExists(i); exists {
			if index >= len(stub.FirstValid) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.FirstValid = stub.FirstValid[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLastValid.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLastValid.EntryExists(i); exists {
			if index >= len(stub.LastValid) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.LastValid = stub.LastValid[index]
			index++
		}
	}
	index = 0
	stub.BitmaskNote.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskNote.EntryExists(i); exists {
			if index >= len(stub.Note) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Note = stub.Note[index]
			index++
		}
	}
	index = 0
	stub.BitmaskGenesisID.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskGenesisID.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.GenesisID = stub.GenesisID
			index++
		}
	}
	index = 0
	stub.BitmaskGenesisHash.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskGenesisHash.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.GenesisHash = stub.GenesisHash
			index++
		}
	}
	index = 0
	stub.BitmaskLease.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLease.EntryExists(i); exists {
			slice, err := getSlice(stub.Lease, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.Lease[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskRekeyTo.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskRekeyTo.EntryExists(i); exists {
			slice, err := getSlice(stub.RekeyTo, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.RekeyTo[:], slice)
			index++
		}
	}
	return nil
}

func reconstructKeyregTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskKeys.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskKeys.EntryExists(i); exists {
			slice, err := getSlice(stub.VotePK, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.VotePK[:], slice)
			slice, err = getSlice(stub.SelectionPK, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.SelectionPK[:], slice)
			if index >= len(stub.VoteKeyDilution) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.VoteKeyDilution = stub.VoteKeyDilution[index]
			index++
		}
	}
	index = 0
	stub.BitmaskVoteFirst.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskVoteFirst.EntryExists(i); exists {
			if index >= len(stub.VoteFirst) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.VoteFirst = stub.VoteFirst[index]
			index++
		}
	}
	index = 0
	stub.BitmaskVoteLast.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskVoteLast.EntryExists(i); exists {
			if index >= len(stub.VoteLast) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.VoteLast = stub.VoteLast[index]
			index++
		}
	}
	stub.BitmaskNonparticipation.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskNonparticipation.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.Nonparticipation = true
		}
	}
	return nil
}

func reconstructPaymentTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskReceiver.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskReceiver.EntryExists(i); exists {
			slice, err := getSlice(stub.Receiver, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.Receiver[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskAmount.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAmount.EntryExists(i); exists {
			if index >= len(stub.Amount) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Amount = stub.Amount[index]
			index++
		}
	}
	index = 0
	stub.BitmaskCloseRemainderTo.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskCloseRemainderTo.EntryExists(i); exists {
			slice, err := getSlice(stub.CloseRemainderTo, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.CloseRemainderTo[:], slice)
			index++
		}
	}
	return nil
}

func reconstructAssetConfigTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskConfigAsset.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskConfigAsset.EntryExists(i); exists {
			if index >= len(stub.ConfigAsset) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ConfigAsset = stub.ConfigAsset[index]
			index++
		}
	}
	return reconstructAssetParams(stub)
}

func reconstructAssetParams(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskTotal.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskTotal.EntryExists(i); exists {
			if index >= len(stub.Total) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.AssetParams.Total = stub.Total[index]
			index++
		}
	}
	index = 0
	stub.BitmaskDecimals.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskDecimals.EntryExists(i); exists {
			if index >= len(stub.Decimals) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.AssetParams.Decimals = stub.Decimals[index]
			index++
		}
	}
	index = 0
	stub.BitmaskDefaultFrozen.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskDefaultFrozen.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.AssetParams.DefaultFrozen = true
			index++
		}
	}
	index = 0
	stub.BitmaskUnitName.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskUnitName.EntryExists(i); exists {
			if index >= len(stub.UnitName) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.AssetParams.UnitName = stub.UnitName[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAssetName.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetName.EntryExists(i); exists {
			if index >= len(stub.AssetName) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.AssetParams.AssetName = stub.AssetName[index]
			index++
		}
	}
	index = 0
	stub.BitmaskURL.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskURL.EntryExists(i); exists {
			if index >= len(stub.URL) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.AssetParams.URL = stub.URL[index]
			index++
		}
	}
	index = 0
	stub.BitmaskMetadataHash.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskMetadataHash.EntryExists(i); exists {
			slice, err := getSlice(stub.MetadataHash, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetParams.MetadataHash[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskManager.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskManager.EntryExists(i); exists {
			slice, err := getSlice(stub.Manager, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetParams.Manager[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskReserve.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskReserve.EntryExists(i); exists {
			slice, err := getSlice(stub.Reserve, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetParams.Reserve[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskFreeze.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFreeze.EntryExists(i); exists {
			slice, err := getSlice(stub.Freeze, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetParams.Freeze[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskClawback.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskClawback.EntryExists(i); exists {
			slice, err := getSlice(stub.Clawback, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetParams.Clawback[:], slice)
			index++
		}
	}
	return nil
}

func reconstructAssetTransferTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskXferAsset.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskXferAsset.EntryExists(i); exists {
			if index >= len(stub.XferAsset) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.XferAsset = stub.XferAsset[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAssetAmount.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetAmount.EntryExists(i); exists {
			if index >= len(stub.AssetAmount) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.AssetAmount = stub.AssetAmount[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAssetSender.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetSender.EntryExists(i); exists {
			slice, err := getSlice(stub.AssetSender, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetSender[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskAssetReceiver.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetReceiver.EntryExists(i); exists {
			slice, err := getSlice(stub.AssetReceiver, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetReceiver[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskAssetCloseTo.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetCloseTo.EntryExists(i); exists {
			slice, err := getSlice(stub.AssetCloseTo, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.AssetCloseTo[:], slice)
			index++
		}
	}
	return nil
}

func reconstructAssetFreezeTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskFreezeAccount.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFreezeAccount.EntryExists(i); exists {
			slice, err := getSlice(stub.FreezeAccount, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.FreezeAccount[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskFreezeAsset.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFreezeAsset.EntryExists(i); exists {
			if index >= len(stub.FreezeAsset) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.FreezeAsset = stub.FreezeAsset[index]
			index++
		}
	}
	stub.BitmaskAssetFrozen.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetFrozen.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.AssetFrozen = true
		}
	}
	return nil
}

func reconstructApplicationCallTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskApplicationID.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskApplicationID.EntryExists(i); exists {
			if index >= len(stub.ApplicationID) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ApplicationID = stub.ApplicationID[index]
			index++
		}
	}
	index = 0
	stub.BitmaskOnCompletion.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskOnCompletion.EntryExists(i); exists {
			b, err := getNibble(stub.OnCompletion, index)
			if err != nil {
				return err
			}
			stub.SignedTxns[i].Txn.OnCompletion = transactions.OnCompletion(b)
			index++
		}
	}
	index = 0
	stub.BitmaskApplicationArgs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskApplicationArgs.EntryExists(i); exists {
			if index >= len(stub.ApplicationArgs) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ApplicationArgs = stub.ApplicationArgs[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAccounts.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAccounts.EntryExists(i); exists {
			if index >= len(stub.Accounts) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Accounts = stub.Accounts[index]
			index++
		}
	}
	index = 0
	stub.BitmaskForeignApps.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskForeignApps.EntryExists(i); exists {
			if index >= len(stub.ForeignApps) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ForeignApps = stub.ForeignApps[index]
			index++
		}
	}
	index = 0
	stub.BitmaskForeignAssets.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskForeignAssets.EntryExists(i); exists {
			if index >= len(stub.ForeignAssets) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ForeignAssets = stub.ForeignAssets[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLocalNumUint.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLocalNumUint.EntryExists(i); exists {
			if index >= len(stub.LocalNumUint) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.LocalStateSchema.NumUint = stub.LocalNumUint[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLocalNumByteSlice.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLocalNumByteSlice.EntryExists(i); exists {
			if index >= len(stub.LocalNumByteSlice) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.LocalStateSchema.NumByteSlice = stub.LocalNumByteSlice[index]
			index++
		}
	}
	index = 0
	stub.BitmaskGlobalNumUint.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskGlobalNumUint.EntryExists(i); exists {
			if index >= len(stub.GlobalNumUint) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.GlobalStateSchema.NumUint = stub.GlobalNumUint[index]
			index++
		}
	}
	index = 0
	stub.BitmaskGlobalNumByteSlice.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskGlobalNumByteSlice.EntryExists(i); exists {
			if index >= len(stub.GlobalNumByteSlice) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.GlobalStateSchema.NumByteSlice = stub.GlobalNumByteSlice[index]
			index++
		}
	}
	index = 0
	stub.BitmaskApprovalProgram.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskApprovalProgram.EntryExists(i); exists {
			if index >= len(stub.ApprovalProgram) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ApprovalProgram = stub.ApprovalProgram[index]
			index++
		}
	}
	index = 0
	stub.BitmaskClearStateProgram.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskClearStateProgram.EntryExists(i); exists {
			if index >= len(stub.ClearStateProgram) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.ClearStateProgram = stub.ClearStateProgram[index]
			index++
		}
	}
	return nil
}

func reconstructCompactCertTxnFields(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskCertRound.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskCertRound.EntryExists(i); exists {
			if index >= len(stub.CertRound) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.CertRound = stub.CertRound[index]
			index++
		}
	}
	index = 0
	stub.BitmaskCertType.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskCertType.EntryExists(i); exists {
			if index >= len(stub.CertType) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.CertType = stub.CertType[index]
			index++
		}
	}
	return reconstructCert(stub)
}

func reconstructCert(stub *txGroupsEncodingStub) error {
	var index int
	index = 0
	stub.BitmaskSigCommit.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSigCommit.EntryExists(i); exists {
			slice, err := getSlice(stub.SigCommit, index, addressSize)
			if err != nil {
				return err
			}
			copy(stub.SignedTxns[i].Txn.Cert.SigCommit[:], slice)
			index++
		}
	}
	index = 0
	stub.BitmaskSignedWeight.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSignedWeight.EntryExists(i); exists {
			if index >= len(stub.SignedWeight) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Cert.SignedWeight = stub.SignedWeight[index]
			index++
		}
	}
	index = 0
	stub.BitmaskSigProofs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSigProofs.EntryExists(i); exists {
			if index >= len(stub.SigProofs) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Cert.SigProofs = stub.SigProofs[index]
			index++
		}
	}
	index = 0
	stub.BitmaskPartProofs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskPartProofs.EntryExists(i); exists {
			if index >= len(stub.PartProofs) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Cert.PartProofs = stub.PartProofs[index]
			index++
		}
	}
	index = 0
	stub.BitmaskReveals.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskReveals.EntryExists(i); exists {
			if index >= len(stub.Reveals) {
				return errDataMissing
			}
			stub.SignedTxns[i].Txn.Cert.Reveals = stub.Reveals[index]
			index++
		}
	}
	return nil
}

func releaseEncodedTransactionGroups(buffer []byte) {
	if buffer == nil {
		return
	}

	protocol.PutEncodingBuf(buffer[:0])
}
