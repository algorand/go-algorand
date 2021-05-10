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
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const maxEncodedTransactionGroup = 30000
const maxEncodedTransactionGroupEntries = 30000
const maxBitmaskSize = (maxEncodedTransactionGroupEntries+7)/8 + 1
const signatureSize = 64
const maxSignatureBytes = maxEncodedTransactionGroupEntries * signatureSize
const addressSize = 32
const maxAddressBytes = maxEncodedTransactionGroupEntries * addressSize

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

	Sig             []byte                  `codec:"sig,allocbound=maxSignatureBytes"`
	BitmaskSig      bitmask                 `codec:"sigbm"`
	Msig            []crypto.MultisigSig    `codec:"msig,allocbound=maxEncodedTransactionGroup"`
	BitmaskMsig     bitmask                 `codec:"msigbm"`
	Lsig            []transactions.LogicSig `codec:"lsig,allocbound=maxEncodedTransactionGroup"`
	BitmaskLsig     bitmask                 `codec:"lsigbm"`
	AuthAddr        []byte                  `codec:"sgnr,allocbound=maxAddressBytes"`
	BitmaskAuthAddr bitmask                 `codec:"sgnrbm"`

	encodedTxns
}

type encodedTxns struct {
	_struct       struct{} `codec:",omitempty,omitemptyarray"`

	TxType        []byte   `codec:"type,allocbound=maxEncodedTransactionGroup"`
	BitmaskTxType bitmask  `codec:"typebm"`

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
	BitmaskVotePK           bitmask        `codec:"votekeybm"`
	SelectionPK             []byte         `codec:"selkey,allocbound=maxAddressBytes"`
	BitmaskSelectionPK      bitmask        `codec:"selkeybm"`
	VoteFirst               []basics.Round `codec:"votefst,allocbound=maxEncodedTransactionGroup"`
	BitmaskVoteFirst        bitmask        `codec:"votefstbm"`
	VoteLast                []basics.Round `codec:"votelst,allocbound=maxEncodedTransactionGroup"`
	BitmaskVoteLast         bitmask        `codec:"votelstbm"`
	VoteKeyDilution         []uint64       `codec:"votekd,allocbound=maxEncodedTransactionGroup"`
	BitmaskVoteKeyDilution  bitmask        `codec:"votekdbm"`
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
	_struct       struct{} `codec:",omitempty,omitemptyarray"`

	Total []uint64 `codec:"t,allocbound=maxEncodedTransactionGroup"`
	BitmaskTotal bitmask              `codec:"tbm"`

	Decimals []uint32 `codec:"dc,allocbound=maxEncodedTransactionGroup"`
	BitmaskDecimals bitmask              `codec:"dcbm"`

	BitmaskDefaultFrozen bitmask              `codec:"dfbm"`

	UnitName []string `codec:"un,allocbound=maxEncodedTransactionGroup"`
	BitmaskUnitName bitmask              `codec:"unbm"`

	AssetName []string `codec:"an,allocbound=maxEncodedTransactionGroup"`
	BitmaskAssetName bitmask              `codec:"anbm"`

	URL []string `codec:"au,allocbound=maxEncodedTransactionGroup"`
	BitmaskURL bitmask              `codec:"aubm"`

	MetadataHash []byte `codec:"am,allocbound=maxAddressBytes"`
	BitmaskMetadataHash bitmask              `codec:"ambm"`

	Manager []byte `codec:"m,allocbound=maxAddressBytes"`
	BitmaskManager bitmask              `codec:"mbm"`

	Reserve []byte `codec:"r,allocbound=maxAddressBytes"`
	BitmaskReserve bitmask              `codec:"rbm"`

	Freeze []byte `codec:"f,allocbound=maxAddressBytes"`
	BitmaskFreeze bitmask              `codec:"fbm"`

	Clawback []byte `codec:"c,allocbound=maxAddressBytes"`
	BitmaskClawback bitmask              `codec:"cbm"`
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

	OnCompletion        []byte `codec:"apan,allocbound=maxEncodedTransactionGroup"`
	BitmaskOnCompletion bitmask                     `codec:"apanbm"`

	ApplicationArgs        []applicationArgs `codec:"apaa,allocbound=maxEncodedTransactionGroup"`
	BitmaskApplicationArgs bitmask           `codec:"apaabm"`

	Accounts        []addresses `codec:"apat,allocbound=maxEncodedTransactionGroup"`
	BitmaskAccounts bitmask     `codec:"apatbm"`

	ForeignApps        []appIndices `codec:"apfa,allocbound=maxEncodedTransactionGroup"`
	BitmaskForeignApps bitmask      `codec:"apfabm"`

	ForeignAssets        []assetIndices `codec:"apas,allocbound=maxEncodedTransactionGroup"`
	BitmaskForeignAssets bitmask        `codec:"apasbm"`

	LocalNumUint      []uint64 `codec:"lnui,allocbound=maxEncodedTransactionGroup"`
	BitmaskLocalNumUint bitmask              `codec:"lnuibm"`
	LocalNumByteSlice []uint64 `codec:"lnbs,allocbound=maxEncodedTransactionGroup"`
	BitmaskLocalNumByteSlice bitmask              `codec:"lnbsbm"`

	GlobalNumUint      []uint64 `codec:"gnui,allocbound=maxEncodedTransactionGroup"`
	BitmaskGlobalNumUint bitmask              `codec:"gnuibm"`
	GlobalNumByteSlice []uint64 `codec:"gnbs,allocbound=maxEncodedTransactionGroup"`
	BitmaskGlobalNumByteSlice bitmask              `codec:"gnbsbm"`

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

	Cert        []compactcert.Cert `codec:"cert,allocbound=maxEncodedTransactionGroup"`
	BitmaskCert bitmask            `codec:"certbm"`
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
		return unknownTx
	}
}

// ByteToTxType converts a byte encoding to TxType
func ByteToTxType(b byte) protocol.TxType {
	txTypes := []protocol.TxType{
		protocol.PaymentTx,
		protocol.KeyRegistrationTx,
		protocol.AssetConfigTx,
		protocol.AssetTransferTx,
		protocol.AssetFreezeTx,
		protocol.ApplicationCallTx,
		protocol.CompactCertTx,
		protocol.UnknownTx,
	}
	return txTypes[b]
}

//msgp:allocbound bitmask maxBitmaskSize
type bitmask []byte

// assumed to be in mode 0, sets bit at index to 1
func (b bitmask) SetBit(index int) {
	byteIndex := index/8 + 1
	b[byteIndex] |= 1 << (index % 8)
}

func (b bitmask) EntryExists(index int) bool {
	byteIndex := index/8 + 1
	return byteIndex < len(b) && (b[byteIndex]&(1<<(index%8)) != 0)
}

func (b *bitmask) trimBitmask(entries int) {
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

func getSlice(b []byte, index int, size int) []byte {
	if index*size+size > len(b) {
		return nil
	}
	return b[index*size : index*size+size]
}

func getHalfByte(b []byte, index int) byte {
	if index > len(b) * 2 {
		return 0
	}
	if index % 2 == 0 {
		return b[index/2] / 16
	} else {
		return b[index/2] % 16
	}
}

func squeezeByteArray(b []byte) []byte {
	compressed := make([]byte, (len(b) + 1) / 2 )
	for index := range compressed {
		compressed[index] = b[index*2]*16
		if index*2+1 < len(b) {
			compressed[index] += b[index*2+1]
		}
	}
	return compressed
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

	setupDeconstructSignedTransactions(&stub)
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

	//return []byte{}

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

	reconstructSignedTransactions(&stub)

	txnGroups = make([]transactions.SignedTxGroup, stub.TransactionGroupCount)
	for index, i := 0, 0; index < int(stub.TotalTransactionsCount); i++ {
		size := 1
		if i < len(stub.TransactionGroupSizes) {
			size = int(stub.TransactionGroupSizes[i]) + 1
		}
		txnGroups[i].Transactions = stub.SignedTxns[index : index+size]
		index += size
	}

	addGroupHashes(txnGroups, int(stub.TotalTransactionsCount), stub.BitmaskGroup)

	return txnGroups, nil
}

func addGroupHashes(txnGroups []transactions.SignedTxGroup, txnCount int, b bitmask) {
	index := 0
	for _, txns := range txnGroups {
		var txGroup transactions.TxGroup
		txGroup.TxGroupHashes = make([]crypto.Digest, len(txns.Transactions))
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

func setupDeconstructSignedTransactions(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAuthAddr = make(bitmask, bitmaskLen)
	stub.AuthAddr = make([]byte, 0, int(stub.TotalTransactionsCount)*addressSize)
	stub.BitmaskLsig = make(bitmask, bitmaskLen)
	stub.Lsig = make([]transactions.LogicSig, 0, int(stub.TotalTransactionsCount))
	stub.BitmaskMsig = make(bitmask, bitmaskLen)
	stub.Msig = make([]crypto.MultisigSig, 0, int(stub.TotalTransactionsCount))
	stub.BitmaskSig = make(bitmask, bitmaskLen)
	stub.Sig = make([]byte, 0, int(stub.TotalTransactionsCount)*signatureSize)
	setupDeconstructTransactions(stub)
}

// deconstructs SignedTxn's into lists of fields and bitmasks
func deconstructSignedTransactions(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	if !txn.Sig.MsgIsZero() {
		stub.BitmaskSig.SetBit(i)
		stub.Sig = append(stub.Sig, txn.Sig[:]...)
	}
	if !txn.Msig.MsgIsZero() {
		stub.BitmaskMsig.SetBit(i)
		stub.Msig = append(stub.Msig, txn.Msig)
	}
	if !txn.Lsig.MsgIsZero() {
		stub.BitmaskLsig.SetBit(i)
		stub.Lsig = append(stub.Lsig, txn.Lsig)
	}
	if !txn.AuthAddr.MsgIsZero() {
		stub.BitmaskAuthAddr.SetBit(i)
		stub.AuthAddr = append(stub.AuthAddr, txn.AuthAddr[:]...)
	}
	deconstructTransactions(stub, i, txn)
}

func finishDeconstructSignedTransactions(stub *txGroupsEncodingStub) {
	stub.BitmaskAuthAddr.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskLsig.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskMsig.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskSig.trimBitmask(int(stub.TotalTransactionsCount))
	finishDeconstructTransactions(stub)
}

func setupDeconstructTransactions(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskTxType = make(bitmask, bitmaskLen)
	stub.TxType = make([]byte, 0, int(stub.TotalTransactionsCount))
	setupDeconstructTxnHeader(stub)
	setupDeconstructKeyregTxnFields(stub)
	setupDeconstructPaymentTxnFields(stub)
	setupDeconstructAssetConfigTxnFields(stub)
	setupDeconstructAssetTransferTxnFields(stub)
	setupDeconstructAssetFreezeTxnFields(stub)
	setupDeconstructApplicationCallTxnFields(stub)
	setupDeconstructCompactCertTxnFields(stub)
}

func deconstructTransactions(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	txTypeByte := TxTypeToByte(txn.Txn.Type)
	if txTypeByte != 0 {
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

func setupDeconstructTxnHeader(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskSender = make(bitmask, bitmaskLen)
	stub.Sender = make([]byte, 0, int(stub.TotalTransactionsCount)*addressSize)
	stub.BitmaskFee = make(bitmask, bitmaskLen)
	stub.Fee = make([]basics.MicroAlgos, 0, int(stub.TotalTransactionsCount))
	stub.BitmaskFirstValid = make(bitmask, bitmaskLen)
	stub.FirstValid = make([]basics.Round, 0, int(stub.TotalTransactionsCount))
	stub.BitmaskLastValid = make(bitmask, bitmaskLen)
	stub.LastValid = make([]basics.Round, 0, int(stub.TotalTransactionsCount))
	stub.BitmaskNote = make(bitmask, bitmaskLen)
	stub.Note = make([][]byte, 0, int(stub.TotalTransactionsCount))
	stub.BitmaskGenesisID = make(bitmask, bitmaskLen)
	stub.BitmaskGenesisHash = make(bitmask, bitmaskLen)
	stub.BitmaskGroup = make(bitmask, bitmaskLen)
	stub.BitmaskLease = make(bitmask, bitmaskLen)
	stub.Lease = make([]byte, 0, int(stub.TotalTransactionsCount)*addressSize)
	stub.BitmaskRekeyTo = make(bitmask, bitmaskLen)
	stub.RekeyTo = make([]byte, 0, int(stub.TotalTransactionsCount)*addressSize)
}

func deconstructTxnHeader(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	if !txn.Txn.Sender.MsgIsZero() {
		stub.BitmaskSender.SetBit(i)
		stub.Sender = append(stub.Sender, txn.Txn.Sender[:]...)
	}
	if !txn.Txn.Fee.MsgIsZero() {
		stub.BitmaskFee.SetBit(i)
		stub.Fee = append(stub.Fee, txn.Txn.Fee)
	}
	if !txn.Txn.FirstValid.MsgIsZero() {
		stub.BitmaskFirstValid.SetBit(i)
		stub.FirstValid = append(stub.FirstValid, txn.Txn.FirstValid)
	}
	if !txn.Txn.LastValid.MsgIsZero() {
		stub.BitmaskLastValid.SetBit(i)
		stub.LastValid = append(stub.LastValid, txn.Txn.LastValid)
	}
	if txn.Txn.Note != nil {
		stub.BitmaskNote.SetBit(i)
		stub.Note = append(stub.Note, txn.Txn.Note)
	}
	if txn.Txn.GenesisID != "" {
		stub.BitmaskGenesisID.SetBit(i)
		stub.GenesisID = txn.Txn.GenesisID
	}
	if !txn.Txn.GenesisHash.MsgIsZero() {
		stub.BitmaskGenesisHash.SetBit(i)
		stub.GenesisHash = txn.Txn.GenesisHash
	}
	if !txn.Txn.Group.MsgIsZero() {
		stub.BitmaskGroup.SetBit(i)
	}
	if txn.Txn.Lease != ([32]byte{}) {
		stub.BitmaskLease.SetBit(i)
		stub.Lease = append(stub.Lease, txn.Txn.Lease[:]...)
	}
	if !txn.Txn.RekeyTo.MsgIsZero() {
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

func setupDeconstructKeyregTxnFields(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskVotePK = make(bitmask, bitmaskLen)
	stub.VotePK = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
	stub.BitmaskSelectionPK = make(bitmask, bitmaskLen)
	stub.SelectionPK = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
	stub.BitmaskVoteFirst = make(bitmask, bitmaskLen)
	stub.VoteFirst = make([]basics.Round, 0, stub.TotalTransactionsCount)
	stub.BitmaskVoteLast = make(bitmask, bitmaskLen)
	stub.VoteLast = make([]basics.Round, 0, stub.TotalTransactionsCount)
	stub.BitmaskVoteKeyDilution = make(bitmask, bitmaskLen)
	stub.VoteKeyDilution = make([]uint64, 0, stub.TotalTransactionsCount)
	stub.BitmaskNonparticipation = make(bitmask, bitmaskLen)
}

func deconstructKeyregTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	if !txn.Txn.VotePK.MsgIsZero() {
		stub.BitmaskVotePK.SetBit(i)
		stub.VotePK = append(stub.VotePK, txn.Txn.VotePK[:]...)
	}
	if !txn.Txn.SelectionPK.MsgIsZero() {
		stub.BitmaskSelectionPK.SetBit(i)
		stub.SelectionPK = append(stub.SelectionPK, txn.Txn.SelectionPK[:]...)
	}
	if !txn.Txn.VoteFirst.MsgIsZero() {
		stub.BitmaskVoteFirst.SetBit(i)
		stub.VoteFirst = append(stub.VoteFirst, txn.Txn.VoteFirst)
	}
	if !txn.Txn.VoteLast.MsgIsZero() {
		stub.BitmaskVoteLast.SetBit(i)
		stub.VoteLast = append(stub.VoteLast, txn.Txn.VoteLast)
	}
	if txn.Txn.VoteKeyDilution != 0 {
		stub.BitmaskVoteKeyDilution.SetBit(i)
		stub.VoteKeyDilution = append(stub.VoteKeyDilution, txn.Txn.VoteKeyDilution)
	}
	if txn.Txn.Nonparticipation {
		stub.BitmaskNonparticipation.SetBit(i)
	}
}

func finishDeconstructKeyregTxnFields(stub *txGroupsEncodingStub) {
	stub.BitmaskVotePK.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskSelectionPK.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskVoteFirst.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskVoteLast.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskVoteKeyDilution.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskNonparticipation.trimBitmask(int(stub.TotalTransactionsCount))
}

func setupDeconstructPaymentTxnFields(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskReceiver = make(bitmask, bitmaskLen)
	stub.Receiver = make([]byte, 0, int(stub.TotalTransactionsCount)*addressSize)
	stub.BitmaskAmount = make(bitmask, bitmaskLen)
	stub.Amount = make([]basics.MicroAlgos, 0, int(stub.TotalTransactionsCount))
	stub.BitmaskCloseRemainderTo = make(bitmask, bitmaskLen)
	stub.CloseRemainderTo = make([]byte, 0, int(stub.TotalTransactionsCount)*addressSize)
}

func deconstructPaymentTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	if !txn.Txn.Receiver.MsgIsZero() {
		stub.BitmaskReceiver.SetBit(i)
		stub.Receiver = append(stub.Receiver, txn.Txn.Receiver[:]...)
	}
	if !txn.Txn.Amount.MsgIsZero() {
		stub.BitmaskAmount.SetBit(i)
		stub.Amount = append(stub.Amount, txn.Txn.Amount)
	}
	if !txn.Txn.CloseRemainderTo.MsgIsZero() {
		stub.BitmaskCloseRemainderTo.SetBit(i)
		stub.CloseRemainderTo = append(stub.CloseRemainderTo, txn.Txn.CloseRemainderTo[:]...)
	}
}

func finishDeconstructPaymentTxnFields(stub *txGroupsEncodingStub) {
	stub.BitmaskReceiver.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAmount.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskCloseRemainderTo.trimBitmask(int(stub.TotalTransactionsCount))
}

func setupDeconstructAssetConfigTxnFields(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskConfigAsset = make(bitmask, bitmaskLen)
	setupDeconstructAssetParams(stub)
}

func deconstructAssetConfigTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	if !txn.Txn.ConfigAsset.MsgIsZero() {
		stub.BitmaskConfigAsset.SetBit(i)
		stub.ConfigAsset = append(stub.ConfigAsset, txn.Txn.ConfigAsset)
	}
	deconstructAssetParams(stub, i, txn)
}

func finishDeconstructAssetConfigTxnFields(stub *txGroupsEncodingStub) {
	stub.BitmaskConfigAsset.trimBitmask(int(stub.TotalTransactionsCount))
	finishDeconstructAssetParams(stub)
}

func setupDeconstructAssetParams(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskTotal = make(bitmask, bitmaskLen)
	stub.Total = make([]uint64, 0, stub.TotalTransactionsCount)
	stub.BitmaskDecimals = make(bitmask, bitmaskLen)
	stub.Decimals = make([]uint32, 0, stub.TotalTransactionsCount)
	stub.BitmaskDefaultFrozen = make(bitmask, bitmaskLen)
	stub.BitmaskUnitName = make(bitmask, bitmaskLen)
	stub.UnitName = make([]string, 0, stub.TotalTransactionsCount)
	stub.BitmaskAssetName = make(bitmask, bitmaskLen)
	stub.AssetName = make([]string, 0, stub.TotalTransactionsCount)
	stub.BitmaskURL = make(bitmask, bitmaskLen)
	stub.URL = make([]string, 0, stub.TotalTransactionsCount)
	stub.BitmaskMetadataHash = make(bitmask, bitmaskLen)
	stub.MetadataHash = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
	stub.BitmaskManager = make(bitmask, bitmaskLen)
	stub.Manager = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
	stub.BitmaskReserve = make(bitmask, bitmaskLen)
	stub.Reserve = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
	stub.BitmaskFreeze = make(bitmask, bitmaskLen)
	stub.Freeze = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
	stub.BitmaskClawback = make(bitmask, bitmaskLen)
	stub.Clawback = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
}

func deconstructAssetParams(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	if txn.Txn.AssetParams.Total != 0 {
		stub.BitmaskTotal.SetBit(i)
		stub.Total = append(stub.Total, txn.Txn.AssetParams.Total)
	}
	if txn.Txn.AssetParams.Decimals != 0 {
		stub.BitmaskDecimals.SetBit(i)
		stub.Decimals = append(stub.Decimals, txn.Txn.AssetParams.Decimals)
	}
	if txn.Txn.AssetParams.DefaultFrozen {
		stub.BitmaskDefaultFrozen.SetBit(i)
	}
	if txn.Txn.AssetParams.UnitName != "" {
		stub.BitmaskUnitName.SetBit(i)
		stub.UnitName = append(stub.UnitName, txn.Txn.AssetParams.UnitName)
	}
	if txn.Txn.AssetParams.AssetName != "" {
		stub.BitmaskAssetName.SetBit(i)
		stub.AssetName = append(stub.AssetName, txn.Txn.AssetParams.AssetName)
	}
	if txn.Txn.AssetParams.URL != "" {
		stub.BitmaskURL.SetBit(i)
		stub.URL = append(stub.URL, txn.Txn.AssetParams.URL)
	}
	if txn.Txn.AssetParams.MetadataHash != [32]byte{} {
		stub.BitmaskMetadataHash.SetBit(i)
		stub.MetadataHash = append(stub.MetadataHash, txn.Txn.AssetParams.MetadataHash[:]...)
	}
	if !txn.Txn.AssetParams.Manager.MsgIsZero() {
		stub.BitmaskManager.SetBit(i)
		stub.Manager = append(stub.Manager, txn.Txn.AssetParams.Manager[:]...)
	}
	if !txn.Txn.AssetParams.Reserve.MsgIsZero() {
		stub.BitmaskReserve.SetBit(i)
		stub.Reserve = append(stub.Reserve, txn.Txn.AssetParams.Reserve[:]...)
	}
	if !txn.Txn.AssetParams.Freeze.MsgIsZero() {
		stub.BitmaskFreeze.SetBit(i)
		stub.Freeze = append(stub.Freeze, txn.Txn.AssetParams.Freeze[:]...)
	}
	if !txn.Txn.AssetParams.Clawback.MsgIsZero() {
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

func setupDeconstructAssetTransferTxnFields(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskXferAsset = make(bitmask, bitmaskLen)
	stub.XferAsset = make([]basics.AssetIndex, 0, stub.TotalTransactionsCount)
	stub.BitmaskAssetAmount = make(bitmask, bitmaskLen)
	stub.AssetAmount = make([]uint64, 0, stub.TotalTransactionsCount)
	stub.BitmaskAssetSender = make(bitmask, bitmaskLen)
	stub.AssetSender = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
	stub.BitmaskAssetReceiver = make(bitmask, bitmaskLen)
	stub.AssetReceiver = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
	stub.BitmaskAssetCloseTo = make(bitmask, bitmaskLen)
	stub.AssetCloseTo = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
}

func deconstructAssetTransferTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	if !txn.Txn.XferAsset.MsgIsZero() {
		stub.BitmaskXferAsset.SetBit(i)
		stub.XferAsset = append(stub.XferAsset, txn.Txn.XferAsset)
	}
	if txn.Txn.AssetAmount != 0 {
		stub.BitmaskAssetAmount.SetBit(i)
		stub.AssetAmount = append(stub.AssetAmount, txn.Txn.AssetAmount)
	}
	if !txn.Txn.AssetSender.MsgIsZero() {
		stub.BitmaskAssetSender.SetBit(i)
		stub.AssetSender = append(stub.AssetSender, txn.Txn.AssetSender[:]...)
	}
	if !txn.Txn.AssetReceiver.MsgIsZero() {
		stub.BitmaskAssetReceiver.SetBit(i)
		stub.AssetReceiver = append(stub.AssetReceiver, txn.Txn.AssetReceiver[:]...)
	}
	if !txn.Txn.AssetCloseTo.MsgIsZero() {
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

func setupDeconstructAssetFreezeTxnFields(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskFreezeAccount = make(bitmask, bitmaskLen)
	stub.FreezeAccount = make([]byte, 0, stub.TotalTransactionsCount*addressSize)
	stub.BitmaskFreezeAsset = make(bitmask, bitmaskLen)
	stub.FreezeAsset = make([]basics.AssetIndex, 0, stub.TotalTransactionsCount)
	stub.BitmaskAssetFrozen = make(bitmask, bitmaskLen)
}

func deconstructAssetFreezeTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	if !txn.Txn.FreezeAccount.MsgIsZero() {
		stub.BitmaskFreezeAccount.SetBit(i)
		stub.FreezeAccount = append(stub.FreezeAccount, txn.Txn.FreezeAccount[:]...)
	}
	if txn.Txn.FreezeAsset != 0 {
		stub.BitmaskFreezeAsset.SetBit(i)
		stub.FreezeAsset = append(stub.FreezeAsset, txn.Txn.FreezeAsset)
	}
	if txn.Txn.AssetFrozen {
		stub.BitmaskAssetFrozen.SetBit(i)
	}
}

func finishDeconstructAssetFreezeTxnFields(stub *txGroupsEncodingStub) {
	stub.BitmaskFreezeAccount.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskFreezeAsset.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskAssetFrozen.trimBitmask(int(stub.TotalTransactionsCount))
}

func setupDeconstructApplicationCallTxnFields(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskApplicationID = make(bitmask, bitmaskLen)
	stub.ApplicationID = make([]basics.AppIndex, 0, stub.TotalTransactionsCount)
	stub.BitmaskOnCompletion = make(bitmask, bitmaskLen)
	stub.OnCompletion = make([]byte, 0, stub.TotalTransactionsCount)
	stub.BitmaskApplicationArgs = make(bitmask, bitmaskLen)
	stub.ApplicationArgs = make([]applicationArgs, 0, stub.TotalTransactionsCount)
	stub.BitmaskAccounts = make(bitmask, bitmaskLen)
	stub.Accounts = make([]addresses, 0, stub.TotalTransactionsCount)
	stub.BitmaskForeignApps = make(bitmask, bitmaskLen)
	stub.ForeignApps = make([]appIndices, 0, stub.TotalTransactionsCount)
	stub.BitmaskForeignAssets = make(bitmask, bitmaskLen)
	stub.ForeignAssets = make([]assetIndices, 0, stub.TotalTransactionsCount)
	stub.BitmaskLocalNumUint = make(bitmask, bitmaskLen)
	stub.LocalNumUint = make([]uint64, 0, stub.TotalTransactionsCount)
	stub.BitmaskLocalNumByteSlice = make(bitmask, bitmaskLen)
	stub.LocalNumByteSlice = make([]uint64, 0, stub.TotalTransactionsCount)
	stub.BitmaskGlobalNumUint = make(bitmask, bitmaskLen)
	stub.GlobalNumUint = make([]uint64, 0, stub.TotalTransactionsCount)
	stub.BitmaskGlobalNumByteSlice = make(bitmask, bitmaskLen)
	stub.GlobalNumByteSlice = make([]uint64, 0, stub.TotalTransactionsCount)
	stub.BitmaskApprovalProgram = make(bitmask, bitmaskLen)
	stub.ApprovalProgram = make([]program, 0, stub.TotalTransactionsCount)
	stub.BitmaskClearStateProgram = make(bitmask, bitmaskLen)
	stub.ClearStateProgram = make([]program, 0, stub.TotalTransactionsCount)
}

func deconstructApplicationCallTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	if !txn.Txn.ApplicationID.MsgIsZero() {
		stub.BitmaskApplicationID.SetBit(i)
		stub.ApplicationID = append(stub.ApplicationID, txn.Txn.ApplicationID)
	}
	if txn.Txn.OnCompletion != 0 {
		stub.BitmaskOnCompletion.SetBit(i)
		stub.OnCompletion = append(stub.OnCompletion, byte(txn.Txn.OnCompletion))
	}
	if txn.Txn.ApplicationArgs != nil {
		stub.BitmaskApplicationArgs.SetBit(i)
		stub.ApplicationArgs = append(stub.ApplicationArgs, txn.Txn.ApplicationArgs)
	}
	if txn.Txn.Accounts != nil {
		stub.BitmaskAccounts.SetBit(i)
		stub.Accounts = append(stub.Accounts, txn.Txn.Accounts)
	}
	if txn.Txn.ForeignApps != nil {
		stub.BitmaskForeignApps.SetBit(i)
		stub.ForeignApps = append(stub.ForeignApps, txn.Txn.ForeignApps)
	}
	if txn.Txn.ForeignAssets != nil {
		stub.BitmaskForeignAssets.SetBit(i)
		stub.ForeignAssets = append(stub.ForeignAssets, txn.Txn.ForeignAssets)
	}
	if !txn.Txn.LocalStateSchema.MsgIsZero() {
		stub.BitmaskLocalNumUint.SetBit(i)
		stub.LocalNumUint = append(stub.LocalNumUint, txn.Txn.LocalStateSchema.NumUint)
	}
	if !txn.Txn.LocalStateSchema.MsgIsZero() {
		stub.BitmaskLocalNumByteSlice.SetBit(i)
		stub.LocalNumByteSlice = append(stub.LocalNumByteSlice, txn.Txn.LocalStateSchema.NumByteSlice)
	}
	if !txn.Txn.GlobalStateSchema.MsgIsZero() {
		stub.BitmaskGlobalNumUint.SetBit(i)
		stub.GlobalNumUint = append(stub.GlobalNumUint, txn.Txn.GlobalStateSchema.NumUint)
	}
	if !txn.Txn.GlobalStateSchema.MsgIsZero() {
		stub.BitmaskGlobalNumByteSlice.SetBit(i)
		stub.GlobalNumByteSlice = append(stub.GlobalNumByteSlice, txn.Txn.GlobalStateSchema.NumByteSlice)
	}
	if txn.Txn.ApprovalProgram != nil {
		stub.BitmaskApprovalProgram.SetBit(i)
		stub.ApprovalProgram = append(stub.ApprovalProgram, txn.Txn.ApprovalProgram)
	}
	if txn.Txn.ClearStateProgram != nil {
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

func setupDeconstructCompactCertTxnFields(stub *txGroupsEncodingStub) {
	bitmaskLen := bytesNeededBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskCertRound = make(bitmask, bitmaskLen)
	stub.CertRound = make([]basics.Round, 0, stub.TotalTransactionsCount)
	stub.BitmaskCertType = make(bitmask, bitmaskLen)
	stub.CertType = make([]protocol.CompactCertType, 0, stub.TotalTransactionsCount)
	stub.BitmaskCert = make(bitmask, bitmaskLen)
	stub.Cert = make([]compactcert.Cert, 0, stub.TotalTransactionsCount)
}

func deconstructCompactCertTxnFields(stub *txGroupsEncodingStub, i int, txn transactions.SignedTxn) {
	if !txn.Txn.CertRound.MsgIsZero() {
		stub.BitmaskCertRound.SetBit(i)
		stub.CertRound = append(stub.CertRound, txn.Txn.CertRound)
	}
	if txn.Txn.CertType != 0 {
		stub.BitmaskCertType.SetBit(i)
		stub.CertType = append(stub.CertType, txn.Txn.CertType)
	}
	if !txn.Txn.Cert.MsgIsZero() {
		stub.BitmaskCert.SetBit(i)
		stub.Cert = append(stub.Cert, txn.Txn.Cert)
	}
}

func finishDeconstructCompactCertTxnFields(stub *txGroupsEncodingStub) {
	stub.BitmaskCertRound.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskCertType.trimBitmask(int(stub.TotalTransactionsCount))
	stub.BitmaskCert.trimBitmask(int(stub.TotalTransactionsCount))
}

func reconstructSignedTransactions(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	stub.BitmaskSig.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSig.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Sig[:], getSlice(stub.Sig, index, signatureSize))
			index++
		}
	}
	index = 0
	stub.BitmaskMsig.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskMsig.EntryExists(i); exists {
			stub.SignedTxns[i].Msig = stub.Msig[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLsig.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLsig.EntryExists(i); exists {
			stub.SignedTxns[i].Lsig = stub.Lsig[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAuthAddr.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAuthAddr.EntryExists(i); exists {
			copy(stub.SignedTxns[i].AuthAddr[:], getSlice(stub.AuthAddr, index, addressSize))
			index++
		}
	}

	reconstructTransactions(stub)
}

func reconstructTransactions(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	stub.BitmaskTxType.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskTxType.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.Type = ByteToTxType(getHalfByte(stub.TxType, index))
			index++
		} else {
			stub.SignedTxns[i].Txn.Type = protocol.PaymentTx
		}
	}

	reconstructTxnHeader(stub)
	reconstructKeyregTxnFields(stub)
	reconstructPaymentTxnFields(stub)
	reconstructAssetConfigTxnFields(stub)
	reconstructAssetTransferTxnFields(stub)
	reconstructAssetFreezeTxnFields(stub)
	reconstructApplicationCallTxnFields(stub)
	reconstructCompactCertTxnFields(stub)
}

func reconstructTxnHeader(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	stub.BitmaskSender.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSender.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.Sender[:], getSlice(stub.Sender, index, addressSize))
			index++
		}
	}
	index = 0
	stub.BitmaskFee.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFee.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.Fee = stub.Fee[index]
			index++
		}
	}
	index = 0
	stub.BitmaskFirstValid.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFirstValid.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.FirstValid = stub.FirstValid[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLastValid.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLastValid.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.LastValid = stub.LastValid[index]
			index++
		}
	}
	index = 0
	stub.BitmaskNote.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskNote.EntryExists(i); exists {
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
			copy(stub.SignedTxns[i].Txn.Lease[:], getSlice(stub.Lease, index, addressSize))
			index++
		}
	}
	index = 0
	stub.BitmaskRekeyTo.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskRekeyTo.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.RekeyTo[:], getSlice(stub.RekeyTo, index, addressSize))
			index++
		}
	}
}

func reconstructKeyregTxnFields(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	stub.BitmaskVotePK.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskVotePK.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.VotePK[:], getSlice(stub.VotePK, index, addressSize))
			index++
		}
	}
	index = 0
	stub.BitmaskSelectionPK.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskSelectionPK.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.SelectionPK[:], getSlice(stub.SelectionPK, index, addressSize))
			index++
		}
	}
	index = 0
	stub.BitmaskVoteFirst.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskVoteFirst.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.VoteFirst = stub.VoteFirst[index]
			index++
		}
	}
	index = 0
	stub.BitmaskVoteLast.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskVoteLast.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.VoteLast = stub.VoteLast[index]
			index++
		}
	}
	index = 0
	stub.BitmaskVoteKeyDilution.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskVoteKeyDilution.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.VoteKeyDilution = stub.VoteKeyDilution[index]
			index++
		}
	}
	stub.BitmaskNonparticipation.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskNonparticipation.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.Nonparticipation = true
		}
	}
}

func reconstructPaymentTxnFields(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	stub.BitmaskReceiver.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskReceiver.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.Receiver[:], getSlice(stub.Receiver, index, addressSize))
			index++
		}
	}
	index = 0
	stub.BitmaskAmount.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAmount.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.Amount = stub.Amount[index]
			index++
		}
	}
	index = 0
	stub.BitmaskCloseRemainderTo.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskCloseRemainderTo.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.CloseRemainderTo[:], getSlice(stub.CloseRemainderTo, index, addressSize))
			index++
		}
	}
}

func reconstructAssetConfigTxnFields(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	stub.BitmaskConfigAsset.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskConfigAsset.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.ConfigAsset = stub.ConfigAsset[index]
			index++
		}
	}
	reconstructAssetParams(stub)
}

func reconstructAssetParams(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	stub.BitmaskTotal.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskTotal.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.AssetParams.Total = stub.Total[index]
			index++
		}
	}
	index = 0
	stub.BitmaskDecimals.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskDecimals.EntryExists(i); exists {
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
			stub.SignedTxns[i].Txn.AssetParams.UnitName = stub.UnitName[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAssetName.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetName.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.AssetParams.AssetName = stub.AssetName[index]
			index++
		}
	}
	index = 0
	stub.BitmaskURL.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskURL.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.AssetParams.URL = stub.URL[index]
			index++
		}
	}
	index = 0
	stub.BitmaskMetadataHash.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskMetadataHash.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.AssetParams.MetadataHash[:], getSlice(stub.MetadataHash, index, addressSize))
			index++
		}
	}
	index = 0
	stub.BitmaskManager.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskManager.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.AssetParams.Manager[:], getSlice(stub.Manager, index, addressSize))
			index++
		}
	}
	index = 0
	stub.BitmaskReserve.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskReserve.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.AssetParams.Reserve[:], getSlice(stub.Reserve, index, addressSize))
			index++
		}
	}
	index = 0
	stub.BitmaskFreeze.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFreeze.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.AssetParams.Freeze[:], getSlice(stub.Freeze, index, addressSize))
			index++
		}
	}
	index = 0
	stub.BitmaskClawback.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskClawback.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.AssetParams.Clawback[:], getSlice(stub.Clawback, index, addressSize))
			index++
		}
	}
}

func reconstructAssetTransferTxnFields(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	stub.BitmaskXferAsset.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskXferAsset.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.XferAsset = stub.XferAsset[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAssetAmount.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetAmount.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.AssetAmount = stub.AssetAmount[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAssetSender.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetSender.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.AssetSender[:], getSlice(stub.AssetSender, index, addressSize))
			index++
		}
	}
	index = 0
	stub.BitmaskAssetReceiver.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetReceiver.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.AssetReceiver[:], getSlice(stub.AssetReceiver, index, addressSize))
			index++
		}
	}
	index = 0
	stub.BitmaskAssetCloseTo.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAssetCloseTo.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.AssetCloseTo[:], getSlice(stub.AssetCloseTo, index, addressSize))
			index++
		}
	}
}

func reconstructAssetFreezeTxnFields(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	stub.BitmaskFreezeAccount.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFreezeAccount.EntryExists(i); exists {
			copy(stub.SignedTxns[i].Txn.FreezeAccount[:], getSlice(stub.FreezeAccount, index, addressSize))
			index++
		}
	}
	index = 0
	stub.BitmaskFreezeAsset.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskFreezeAsset.EntryExists(i); exists {
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
}

func reconstructApplicationCallTxnFields(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	stub.BitmaskApplicationID.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskApplicationID.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.ApplicationID = stub.ApplicationID[index]
			index++
		}
	}
	index = 0
	stub.BitmaskOnCompletion.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskOnCompletion.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.OnCompletion = transactions.OnCompletion(getHalfByte(stub.OnCompletion, index))
			index++
		}
	}
	index = 0
	stub.BitmaskApplicationArgs.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskApplicationArgs.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.ApplicationArgs = stub.ApplicationArgs[index]
			index++
		}
	}
	index = 0
	stub.BitmaskAccounts.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskAccounts.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.Accounts = stub.Accounts[index]
			index++
		}
	}
	index = 0
	stub.BitmaskForeignApps.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskForeignApps.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.ForeignApps = stub.ForeignApps[index]
			index++
		}
	}
	index = 0
	stub.BitmaskForeignAssets.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskForeignAssets.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.ForeignAssets = stub.ForeignAssets[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLocalNumUint.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLocalNumUint.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.LocalStateSchema.NumUint = stub.LocalNumUint[index]
			index++
		}
	}
	index = 0
	stub.BitmaskLocalNumByteSlice.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskLocalNumByteSlice.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.LocalStateSchema.NumByteSlice = stub.LocalNumByteSlice[index]
			index++
		}
	}
	index = 0
	stub.BitmaskGlobalNumUint.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskGlobalNumUint.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.GlobalStateSchema.NumUint = stub.GlobalNumUint[index]
			index++
		}
	}
	index = 0
	stub.BitmaskGlobalNumByteSlice.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskGlobalNumByteSlice.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.GlobalStateSchema.NumByteSlice = stub.GlobalNumByteSlice[index]
			index++
		}
	}
	index = 0
	stub.BitmaskApprovalProgram.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskApprovalProgram.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.ApprovalProgram = stub.ApprovalProgram[index]
			index++
		}
	}
	index = 0
	stub.BitmaskClearStateProgram.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskClearStateProgram.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.ClearStateProgram = stub.ClearStateProgram[index]
			index++
		}
	}
}

func reconstructCompactCertTxnFields(stub *txGroupsEncodingStub) {
	var index int
	index = 0
	stub.BitmaskCertRound.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskCertRound.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.CertRound = stub.CertRound[index]
			index++
		}
	}
	index = 0
	stub.BitmaskCertType.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskCertType.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.CertType = stub.CertType[index]
			index++
		}
	}
	index = 0
	stub.BitmaskCert.expandBitmask(int(stub.TotalTransactionsCount))
	for i := range stub.SignedTxns {
		if exists := stub.BitmaskCert.EntryExists(i); exists {
			stub.SignedTxns[i].Txn.Cert = stub.Cert[index]
			index++
		}
	}
}

func releaseEncodedTransactionGroups(buffer []byte) {
	if buffer == nil {
		return
	}

	protocol.PutEncodingBuf(buffer[:0])
}
