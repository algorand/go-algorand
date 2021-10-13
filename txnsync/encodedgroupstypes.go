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
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/protocol"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/pooldata"
)

const maxEncodedTransactionGroups = 30000
const maxEncodedTransactionGroupEntries = 30000
const maxBitmaskSize = (maxEncodedTransactionGroupEntries+7)/8 + 1
const maxSignatureBytes = maxEncodedTransactionGroupEntries * len(crypto.Signature{})
const maxAddressBytes = maxEncodedTransactionGroupEntries * crypto.DigestSize

var errInvalidTxType = errors.New("invalid txtype")

//msgp:allocbound txnGroups maxEncodedTransactionGroupEntries
type txnGroups pooldata.SignedTxnSlice //nolint:unused

// old data structure for encoding (only used for testing)
type txGroupsEncodingStubOld struct { //nolint:unused
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	TxnGroups []txnGroups `codec:"t,allocbound=maxEncodedTransactionGroups"`
}

type txGroupsEncodingStub struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	TotalTransactionsCount uint64 `codec:"ttc"`
	TransactionGroupCount  uint64 `codec:"tgc"`
	TransactionGroupSizes  []byte `codec:"tgs,allocbound=maxEncodedTransactionGroups"`

	encodedSignedTxns
}

type encodedSignedTxns struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	Sig        []byte  `codec:"sig,allocbound=maxSignatureBytes"`
	BitmaskSig bitmask `codec:"sigbm"`

	encodedMsigs
	encodedLsigs

	AuthAddr        []byte  `codec:"sgnr,allocbound=maxAddressBytes"`
	BitmaskAuthAddr bitmask `codec:"sgnrbm"`

	encodedTxns
}

type encodedMsigs struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	Version          []byte  `codec:"msigv,allocbound=maxEncodedTransactionGroups"`
	BitmaskVersion   bitmask `codec:"msigvbm"`
	Threshold        []byte  `codec:"msigthr,allocbound=maxEncodedTransactionGroups"`
	BitmaskThreshold bitmask `codec:"msigthrbm"`
	// splitting subsigs further make the code much more complicated / does not give gains
	Subsigs        [][]crypto.MultisigSubsig `codec:"subsig,allocbound=maxEncodedTransactionGroups,allocbound=crypto.MaxMultisig"`
	BitmaskSubsigs bitmask                   `codec:"subsigsbm"`
}

type encodedLsigs struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	Logic            [][]byte   `codec:"lsigl,allocbound=maxEncodedTransactionGroups,allocbound=config.MaxLogicSigMaxSize"`
	BitmaskLogic     bitmask    `codec:"lsiglbm"`
	LogicArgs        [][][]byte `codec:"lsigarg,allocbound=maxEncodedTransactionGroups,allocbound=transactions.EvalMaxArgs,allocbound=config.MaxLogicSigMaxSize"`
	BitmaskLogicArgs bitmask    `codec:"lsigargbm"`
}

type encodedTxns struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	TxType        []byte  `codec:"type,allocbound=maxEncodedTransactionGroups"`
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
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	Sender            []byte              `codec:"snd,allocbound=maxAddressBytes"`
	BitmaskSender     bitmask             `codec:"sndbm"`
	Fee               []basics.MicroAlgos `codec:"fee,allocbound=maxEncodedTransactionGroups"`
	BitmaskFee        bitmask             `codec:"feebm"`
	FirstValid        []basics.Round      `codec:"fv,allocbound=maxEncodedTransactionGroups"`
	BitmaskFirstValid bitmask             `codec:"fvbm"`
	LastValid         []basics.Round      `codec:"lv,allocbound=maxEncodedTransactionGroups"`
	BitmaskLastValid  bitmask             `codec:"lvbm"`
	Note              [][]byte            `codec:"note,allocbound=maxEncodedTransactionGroups,allocbound=config.MaxTxnNoteBytes"`
	BitmaskNote       bitmask             `codec:"notebm"`
	BitmaskGenesisID  bitmask             `codec:"genbm"`

	BitmaskGroup bitmask `codec:"grpbm"`

	Lease        []byte  `codec:"lx,allocbound=maxAddressBytes"`
	BitmaskLease bitmask `codec:"lxbm"`

	RekeyTo        []byte  `codec:"rekey,allocbound=maxAddressBytes"`
	BitmaskRekeyTo bitmask `codec:"rekeybm"`
}

type encodedKeyregTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	VotePK                  []byte         `codec:"votekey,allocbound=maxAddressBytes"`
	SelectionPK             []byte         `codec:"selkey,allocbound=maxAddressBytes"`
	VoteFirst               []basics.Round `codec:"votefst,allocbound=maxEncodedTransactionGroups"`
	BitmaskVoteFirst        bitmask        `codec:"votefstbm"`
	VoteLast                []basics.Round `codec:"votelst,allocbound=maxEncodedTransactionGroups"`
	BitmaskVoteLast         bitmask        `codec:"votelstbm"`
	VoteKeyDilution         []uint64       `codec:"votekd,allocbound=maxEncodedTransactionGroups"`
	BitmaskKeys             bitmask        `codec:"votekbm"`
	BitmaskNonparticipation bitmask        `codec:"nonpartbm"`
	HasValidRoot            []bool         `codec:"vldrt,allocbound=maxEncodedTransactionGroups"`
	CommitmentRoot          []byte         `codec:"comt,allocbound=maxEncodedTransactionGroups"`
}

type encodedPaymentTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	Receiver        []byte              `codec:"rcv,allocbound=maxAddressBytes"`
	BitmaskReceiver bitmask             `codec:"rcvbm"`
	Amount          []basics.MicroAlgos `codec:"amt,allocbound=maxEncodedTransactionGroups"`
	BitmaskAmount   bitmask             `codec:"amtbm"`

	CloseRemainderTo        []byte  `codec:"close,allocbound=maxAddressBytes"`
	BitmaskCloseRemainderTo bitmask `codec:"closebm"`
}

type encodedAssetConfigTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	ConfigAsset        []basics.AssetIndex `codec:"caid,allocbound=maxEncodedTransactionGroups"`
	BitmaskConfigAsset bitmask             `codec:"caidbm"`

	encodedAssetParams
}

type encodedAssetParams struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	Total        []uint64 `codec:"t,allocbound=maxEncodedTransactionGroups"`
	BitmaskTotal bitmask  `codec:"tbm"`

	Decimals        []uint32 `codec:"dc,allocbound=maxEncodedTransactionGroups"`
	BitmaskDecimals bitmask  `codec:"dcbm"`

	BitmaskDefaultFrozen bitmask `codec:"dfbm"`

	UnitName        []string `codec:"un,allocbound=maxEncodedTransactionGroups"`
	BitmaskUnitName bitmask  `codec:"unbm"`

	AssetName        []string `codec:"an,allocbound=maxEncodedTransactionGroups"`
	BitmaskAssetName bitmask  `codec:"anbm"`

	URL        []string `codec:"au,allocbound=maxEncodedTransactionGroups"`
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
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	XferAsset        []basics.AssetIndex `codec:"xaid,allocbound=maxEncodedTransactionGroups"`
	BitmaskXferAsset bitmask             `codec:"xaidbm"`

	AssetAmount        []uint64 `codec:"aamt,allocbound=maxEncodedTransactionGroups"`
	BitmaskAssetAmount bitmask  `codec:"aamtbm"`

	AssetSender        []byte  `codec:"asnd,allocbound=maxAddressBytes"`
	BitmaskAssetSender bitmask `codec:"asndbm"`

	AssetReceiver        []byte  `codec:"arcv,allocbound=maxAddressBytes"`
	BitmaskAssetReceiver bitmask `codec:"arcvbm"`

	AssetCloseTo        []byte  `codec:"aclose,allocbound=maxAddressBytes"`
	BitmaskAssetCloseTo bitmask `codec:"aclosebm"`
}

type encodedAssetFreezeTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	FreezeAccount        []byte  `codec:"fadd,allocbound=maxAddressBytes"`
	BitmaskFreezeAccount bitmask `codec:"faddbm"`

	FreezeAsset        []basics.AssetIndex `codec:"faid,allocbound=maxEncodedTransactionGroups"`
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

//msgp:allocbound program config.MaxAvailableAppProgramLen
type program []byte

type encodedApplicationCallTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	ApplicationID        []basics.AppIndex `codec:"apid,allocbound=maxEncodedTransactionGroups"`
	BitmaskApplicationID bitmask           `codec:"apidbm"`

	OnCompletion        []byte  `codec:"apan,allocbound=maxEncodedTransactionGroups"`
	BitmaskOnCompletion bitmask `codec:"apanbm"`

	ApplicationArgs        []applicationArgs `codec:"apaa,allocbound=maxEncodedTransactionGroups"`
	BitmaskApplicationArgs bitmask           `codec:"apaabm"`

	Accounts        []addresses `codec:"apat,allocbound=maxEncodedTransactionGroups"`
	BitmaskAccounts bitmask     `codec:"apatbm"`

	ForeignApps        []appIndices `codec:"apfa,allocbound=maxEncodedTransactionGroups"`
	BitmaskForeignApps bitmask      `codec:"apfabm"`

	ForeignAssets        []assetIndices `codec:"apas,allocbound=maxEncodedTransactionGroups"`
	BitmaskForeignAssets bitmask        `codec:"apasbm"`

	LocalNumUint             []uint64 `codec:"lnui,allocbound=maxEncodedTransactionGroups"`
	BitmaskLocalNumUint      bitmask  `codec:"lnuibm"`
	LocalNumByteSlice        []uint64 `codec:"lnbs,allocbound=maxEncodedTransactionGroups"`
	BitmaskLocalNumByteSlice bitmask  `codec:"lnbsbm"`

	GlobalNumUint             []uint64 `codec:"gnui,allocbound=maxEncodedTransactionGroups"`
	BitmaskGlobalNumUint      bitmask  `codec:"gnuibm"`
	GlobalNumByteSlice        []uint64 `codec:"gnbs,allocbound=maxEncodedTransactionGroups"`
	BitmaskGlobalNumByteSlice bitmask  `codec:"gnbsbm"`

	ApprovalProgram        []program `codec:"apap,allocbound=maxEncodedTransactionGroups"`
	BitmaskApprovalProgram bitmask   `codec:"apapbm"`

	ClearStateProgram        []program `codec:"apsu,allocbound=maxEncodedTransactionGroups"`
	BitmaskClearStateProgram bitmask   `codec:"apsubm"`

	ExtraProgramPages        []uint32 `codec:"apep,allocbound=maxEncodedTransactionGroups"`
	BitmaskExtraProgramPages bitmask  `codec:"apepbm"`
}

type encodedCompactCertTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	CertRound        []basics.Round `codec:"certrnd,allocbound=maxEncodedTransactionGroups"`
	BitmaskCertRound bitmask        `codec:"certrndbm"`

	CertType        []protocol.CompactCertType `codec:"certtype,allocbound=maxEncodedTransactionGroups"`
	BitmaskCertType bitmask                    `codec:"certtypebm"`

	encodedCert
}

//msgp:allocbound certProofs compactcert.MaxProofDigests
type certProofs []crypto.GenericDigest

//msgp:allocbound revealMap compactcert.MaxReveals
type revealMap map[uint64]compactcert.Reveal

// SortUint64 implements sorting by uint64 keys for
// canonical encoding of maps in msgpack format.
type SortUint64 = compactcert.SortUint64

type encodedCert struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"` //nolint:structcheck,unused

	SigCommit        []crypto.GenericDigest `codec:"certc,allocbound=maxAddressBytes"`
	BitmaskSigCommit bitmask                `codec:"certcbm"`

	SignedWeight        []uint64 `codec:"certw,allocbound=maxEncodedTransactionGroups"`
	BitmaskSignedWeight bitmask  `codec:"certwbm"`

	SigProofs        []certProofs `codec:"certS,allocbound=maxEncodedTransactionGroups"`
	BitmaskSigProofs bitmask      `codec:"certSbm"`

	SigProofHashTypes []uint64 `codec:"certSH,allocbound=maxEncodedTransactionGroups"`
	BitmaskSigsHash   bitmask  `codec:"certSHbm"`

	PartProofs        []certProofs `codec:"certP,allocbound=maxEncodedTransactionGroups"`
	BitmaskPartProofs bitmask      `codec:"certPbm"`

	PartProofHashTypes []uint64 `codec:"certPH,allocbound=maxEncodedTransactionGroups"`
	BitmaskPartHash    bitmask  `codec:"certPHbm"`

	Reveals        []revealMap `codec:"certr,allocbound=maxEncodedTransactionGroups"`
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
