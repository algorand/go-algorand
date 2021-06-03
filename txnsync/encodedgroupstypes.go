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
	"errors"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const maxEncodedTransactionGroup = 30000
const maxEncodedTransactionGroupEntries = 30000
const maxBitmaskSize = (maxEncodedTransactionGroupEntries+7)/8 + 1
const maxSignatureBytes = maxEncodedTransactionGroupEntries * len(crypto.Signature{})
const maxAddressBytes = maxEncodedTransactionGroupEntries * crypto.DigestSize

var errInvalidTxType = errors.New("invalid txtype")

//msgp:allocbound txnGroups maxEncodedTransactionGroupEntries
type txnGroups []transactions.SignedTxn

// old data structure for encoding (only used for testing)
type txGroupsEncodingStubOld struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	TxnGroups []txnGroups `codec:"t,allocbound=maxEncodedTransactionGroup"`
}

type txGroupsEncodingStub struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	TotalTransactionsCount uint64 `codec:"ttc"`
	TransactionGroupCount  uint64 `codec:"tgc"`
	TransactionGroupSizes  []byte `codec:"tgs,allocbound=maxEncodedTransactionGroup"`

	encodedSignedTxns
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

	Version          []byte  `codec:"msigv,allocbound=maxEncodedTransactionGroup"`
	BitmaskVersion   bitmask `codec:"msigvbm"`
	Threshold        []byte  `codec:"msigthr,allocbound=maxEncodedTransactionGroup"`
	BitmaskThreshold bitmask `codec:"msigthrbm"`
	// splitting subsigs further make the code much more complicated / does not give gains
	Subsigs        [][]crypto.MultisigSubsig `codec:"subsig,allocbound=maxEncodedTransactionGroup,allocbound=crypto.MaxMultisig"`
	BitmaskSubsigs bitmask                   `codec:"subsigsbm"`
}

type encodedLsigs struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

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

	Sender            []byte              `codec:"snd,allocbound=maxAddressBytes"`
	BitmaskSender     bitmask             `codec:"sndbm"`
	Fee               []basics.MicroAlgos `codec:"fee,allocbound=maxEncodedTransactionGroup"`
	BitmaskFee        bitmask             `codec:"feebm"`
	FirstValid        []basics.Round      `codec:"fv,allocbound=maxEncodedTransactionGroup"`
	BitmaskFirstValid bitmask             `codec:"fvbm"`
	LastValid         []basics.Round      `codec:"lv,allocbound=maxEncodedTransactionGroup"`
	BitmaskLastValid  bitmask             `codec:"lvbm"`
	Note              [][]byte            `codec:"note,allocbound=maxEncodedTransactionGroup,allocbound=config.MaxTxnNoteBytes"`
	BitmaskNote       bitmask             `codec:"notebm"`
	BitmaskGenesisID  bitmask             `codec:"genbm"`

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
func TxTypeToByte(t protocol.TxType) (byte, error) {
	switch t {
	case protocol.PaymentTx:
		return paymentTx, nil
	case protocol.KeyRegistrationTx:
		return keyRegistrationTx, nil
	case protocol.AssetConfigTx:
		return assetConfigTx, nil
	case protocol.AssetTransferTx:
		return assetTransferTx, nil
	case protocol.AssetFreezeTx:
		return assetFreezeTx, nil
	case protocol.ApplicationCallTx:
		return applicationCallTx, nil
	case protocol.CompactCertTx:
		return compactCertTx, nil
	default:
		return unknownTx, errInvalidTxType
	}
}

// ByteToTxType converts a byte encoding to TxType
func ByteToTxType(b byte) protocol.TxType {
	if int(b) >= len(protocol.TxnTypes) {
		return protocol.UnknownTx
	}
	return protocol.TxnTypes[b]
}
