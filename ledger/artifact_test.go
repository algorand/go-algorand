// Copyright (C) 2019-2022 Algorand, Inc.
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

package ledger

import (
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

/* test/benchmark real programs found in the wild (testnet/mainnet).
 */

// BenchmarkTinyMan tries to reproduce
// https://algoexplorer.io/tx/group/d1bUcqFbNZDMIdcreM9Vw2jzOIZIa2UzDgTTlr2Sl4o%3D
// which is an algo to USDC swap.  The source code below is extracted from
// algoexplorer, which adds some unusual stuff as comments
func BenchmarkTinyMan(b *testing.B) {
	lsig := `
	#pragma version 4
	intcblock 1 0 0 31566704 3 4 5 6
	intc_3 // 31566704
	intc_2 // 0
	>
	assert
	txn CloseRemainderTo // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
	global ZeroAddress
	==
	assert
	txn AssetCloseTo // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
	global ZeroAddress
	==
	assert
	txn RekeyTo // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
	global ZeroAddress
	==
	assert
	global GroupSize // size=4
	intc_0 // 1
	>
	assert
	gtxn 1 Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 1 TypeEnum
	intc 7 // 6
	==
	assert
	gtxn 1 ApplicationID // id=552635992
	pushint 552635992
	==
	assert						// PC=65
	gtxn 1 OnCompletion
	intc_0 // 1
	==
	gtxn 1 NumAppArgs // index=2
	intc 4 // 3
	==
	&&
	gtxna 1 ApplicationArgs 0 // arg=73776170
	pushbytes 0x626f6f747374726170 // "bootstrap"
	==
	&&
	bnz label1
	gtxn 1 OnCompletion
	intc_1 // 0
	==
	assert
	gtxn 1 NumAppArgs // index=2
	pushint 2
	==
	gtxna 1 ApplicationArgs 0 // arg=73776170
	pushbytes 0x73776170 // "swap"
	==
	&&
	bnz label2
	gtxn 1 NumAppArgs // index=2
	intc_0 // 1
	==
	assert
	gtxna 1 ApplicationArgs 0 // arg=73776170
	pushbytes 0x6d696e74 // "mint"
	==
	bnz label3
	gtxna 1 ApplicationArgs 0 // arg=73776170
	pushbytes 0x6275726e // "burn"
	==
	bnz label4
	gtxna 1 ApplicationArgs 0 // arg=73776170
	pushbytes 0x72656465656d // "redeem"
	==
	bnz label5
	gtxna 1 ApplicationArgs 0 // arg=73776170
	pushbytes 0x66656573 // "fees"
	==
	bnz label6
	err
label1:
	intc 6 // 5
	intc 5 // 4
	intc_2 // 0
	intc_1 // 0
	==
	select
	global GroupSize // size=4
	==
	assert
	gtxna 1 ApplicationArgs 1 // arg=666f
	btoi
	intc_3 // 31566704
	==
	gtxna 1 ApplicationArgs 2
	btoi
	intc_2 // 0
	==
	&&
	assert
	gtxn 2 Sender // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 2 TypeEnum
	intc 4 // 3
	==
	assert
	gtxn 2 ConfigAsset // id=0
	intc_1 // 0
	==
	assert
	gtxn 2 ConfigAssetTotal // total=0.
	intc_1 // 0
	~
	==
	assert
	gtxn 2 ConfigAssetDecimals // dec=0
	intc 7 // 6
	==
	assert
	gtxn 2 ConfigAssetDefaultFrozen // default=false
	intc_1 // 0
	==
	assert
	gtxn 2 ConfigAssetUnitName // 
	pushbytes 0x544d504f4f4c3131 // "TMPOOL11"
	==
	assert
	gtxn 2 ConfigAssetName // 
	substring 0 15
	pushbytes 0x54696e796d616e506f6f6c312e3120 // "TinymanPool1.1 "
	==
	assert
	gtxn 2 ConfigAssetURL // 
	pushbytes 0x68747470733a2f2f74696e796d616e2e6f7267 // "https://tinyman.org"
	==
	assert
	gtxn 2 ConfigAssetManager
	global ZeroAddress
	==
	assert
	gtxn 2 ConfigAssetReserve
	global ZeroAddress
	==
	assert
	gtxn 2 ConfigAssetFreeze
	global ZeroAddress
	==
	assert
	gtxn 2 ConfigAssetClawback
	global ZeroAddress
	==
	assert
	gtxn 3 Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 3 TypeEnum
	intc 5 // 4
	==
	assert
	gtxn 3 XferAsset // id=0
	intc_3 // 31566704
	==
	assert
	gtxn 3 AssetReceiver // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 3 AssetAmount
	intc_1 // 0
	==
	assert
	intc_2 // 0
	intc_1 // 0
	!=
	bnz label7
	gtxn 1 Fee // 0.001000
	gtxn 2 Fee // 0.001000
	+
	gtxn 3 Fee // 0.001000
	+
	store 1
	b label8
label7:
	gtxn 4 Sender
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 4 TypeEnum
	intc 5 // 4
	==
	assert
	gtxn 4 XferAsset
	intc_2 // 0
	==
	assert
	gtxn 4 AssetReceiver
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 4 AssetAmount
	intc_1 // 0
	==
	assert
	gtxn 1 Fee // 0.001000
	gtxn 2 Fee // 0.001000
	+
	gtxn 3 Fee // 0.001000
	+
	gtxn 4 Fee
	+
	store 1
	b label8
label3:
	global GroupSize // size=4
	intc 6 // 5
	==
	assert
	gtxna 1 Accounts 1
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	!=
	assert
	gtxna 1 Accounts 1
	gtxn 4 AssetReceiver
	==
	assert
	gtxn 2 Sender // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	!=
	assert
	gtxn 2 AssetReceiver // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 3 Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	gtxn 2 Sender // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	==
	assert
	gtxn 2 XferAsset // id=31566704
	intc_3 // 31566704
	==
	assert
	gtxn 3 AssetReceiver // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
	gtxn 3 Receiver // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	gtxn 3 TypeEnum
	intc_0 // 1
	==
	select
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 3 XferAsset // id=0
	intc_1 // 0
	gtxn 3 TypeEnum
	intc_0 // 1
	==
	select
	intc_2 // 0
	==
	assert
	gtxn 4 Sender
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 4 AssetReceiver
	gtxn 2 Sender // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	==
	assert
	gtxn 1 Fee // 0.001000
	gtxn 4 Fee
	+
	store 1
	b label8
label4:
	global GroupSize // size=4
	intc 6 // 5
	==
	assert
	gtxna 1 Accounts 1
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	!=
	assert
	gtxna 1 Accounts 1
	gtxn 2 AssetReceiver // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 3 AssetReceiver // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
	gtxn 3 Receiver // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	gtxn 3 TypeEnum
	intc_0 // 1
	==
	select
	gtxna 1 Accounts 1
	==
	assert
	gtxn 2 Sender // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 2 AssetReceiver // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	gtxn 4 Sender
	==
	assert
	gtxn 2 XferAsset // id=31566704
	intc_3 // 31566704
	==
	assert
	gtxn 3 Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 3 AssetReceiver // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
	gtxn 3 Receiver // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	gtxn 3 TypeEnum
	intc_0 // 1
	==
	select
	gtxn 4 Sender
	==
	assert
	gtxn 3 XferAsset // id=0
	intc_1 // 0
	gtxn 3 TypeEnum
	intc_0 // 1
	==
	select
	intc_2 // 0
	==
	assert
	gtxn 4 Sender
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	!=
	assert
	gtxn 4 AssetReceiver
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 1 Fee // 0.001000
	gtxn 2 Fee // 0.001000
	+
	gtxn 3 Fee // 0.001000
	+
	store 1
	b label8
label2:							// swap
	global GroupSize // size=4
	intc 5 // 4
	==
	assert
	gtxna 1 Accounts 1
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	!=
	assert
	gtxn 2 Sender // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	gtxna 1 Accounts 1
	==
	assert						// PC=718
	gtxn 2 Sender // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	!=
	assert
	gtxn 3 Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert						// PC=732
	gtxn 2 AssetReceiver // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	gtxn 2 Receiver // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
	gtxn 2 TypeEnum
	intc_0 // 1
	==
	select
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert
	gtxn 3 AssetReceiver // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
	gtxn 3 Receiver // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	gtxn 3 TypeEnum
	intc_0 // 1
	==
	select
	gtxn 2 Sender // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	==
	assert						// PC=765
	gtxn 1 Fee // 0.001000
	gtxn 3 Fee // 0.001000
	+
	store 1
	b label8
label5:
	global GroupSize // size=4
	intc 4 // 3
	==
	assert
	gtxna 1 Accounts 1
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	!=
	assert
	gtxn 2 AssetReceiver // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	gtxn 2 Receiver // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
	gtxn 2 TypeEnum
	intc_0 // 1
	==
	select
	gtxna 1 Accounts 1
	==
	assert
	gtxn 1 Fee // 0.001000
	gtxn 2 Fee // 0.001000
	+
	store 1
	b label8
label6:
	global GroupSize // size=4
	intc 4 // 3
	==
	assert
	gtxn 1 Fee // 0.001000
	gtxn 2 Fee // 0.001000
	+
	store 1
	b label8
label8:
	gtxn 0 Sender // W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	!=
	assert
	gtxn 0 Receiver // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	txn Sender // FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA
	==
	assert						// PC=853
	gtxn 0 Amount // 0.002000
	load 1
	>=
	return
`
	ops, err := logic.AssembleString(lsig)
	require.NoError(b, err)

	user, err := basics.UnmarshalChecksumAddress("W2IZ3EHDRW2IQNPC33CI2CXSLMFCFICVKQVWIYLJWXCTD765RW47ONNCEY")
	require.NoError(b, err)

	luser, err := basics.UnmarshalChecksumAddress("FPOU46NBKTWUZCNMNQNXRWNW3SMPOOK4ZJIN5WSILCWP662ANJLTXVRUKA")
	require.NoError(b, err)

	fees := txntest.Txn{
		Type:     "pay",
		Fee:      1000,
		Sender:   user,
		Receiver: luser,
		Amount:   2000, // must cover the luser fees in appcall and withdraw
	}
	appcall := txntest.Txn{
		Type:          "appl",
		Fee:           1000,
		Sender:        luser,
		ApplicationID: 552635992,
		Accounts:      []basics.Address{user},
	}.Args("swap", "fo")
	deposit := txntest.Txn{
		Type:          "axfer",
		Fee:           1000,
		Sender:        user,
		AssetReceiver: luser,
	}
	withdraw := txntest.Txn{
		Type:     "pay",
		Fee:      1000,
		Sender:   luser,
		Receiver: user,
	}
	stxns := txntest.SignedTxns(&fees, appcall, &deposit, &withdraw)
	stxns[1].Lsig.Logic = ops.Program
	stxns[3].Lsig.Logic = ops.Program
	txgroup := transactions.WrapSignedTxnsWithAD(stxns)

	b.Run("eval-signature", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			proto := config.Consensus[protocol.ConsensusCurrentVersion]
			ep := logic.EvalParams{
				Proto:     &proto,
				TxnGroup:  txgroup,
				SigLedger: &logic.NoHeaderLedger{},
			}
			pass, err := logic.EvalSignature(1, &ep)
			require.NoError(b, err)
			require.True(b, pass)
			pass, err = logic.EvalSignature(3, &ep)
			require.NoError(b, err)
			require.True(b, pass)
		}
	})

	hdr := bookkeeping.BlockHeader{
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: protocol.ConsensusCurrentVersion,
		},
	}

	// add in some signatures, so TxnGroup can succeed.  A randomly generated
	// private key. The actual value does not matter, as long as this is a valid
	// private key.
	signer := crypto.PrivateKey{
		128, 128, 92, 23, 212, 119, 175, 51, 157, 2, 165,
		215, 137, 37, 82, 42, 52, 227, 54, 41, 243, 67,
		141, 76, 208, 17, 199, 17, 140, 46, 113, 0, 159,
		50, 105, 52, 77, 104, 118, 200, 104, 220, 105, 21,
		147, 162, 191, 236, 115, 201, 197, 128, 8, 91, 224,
		78, 104, 209, 2, 185, 110, 28, 42, 97,
	}
	secrets, err := crypto.SecretKeyToSignatureSecrets(signer)
	stxns[0] = stxns[0].Txn.Sign(secrets)
	stxns[2] = stxns[2].Txn.Sign(secrets)
	b.Run("group-check-actual", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := verify.TxnGroup(stxns, hdr, nil, &logic.NoHeaderLedger{})
			require.NoError(b, err)
		}
	})
	stxns[1] = stxns[1].Txn.Sign(secrets)
	stxns[3] = stxns[3].Txn.Sign(secrets)
	b.Run("group-check-all-crypto", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := verify.TxnGroup(stxns, hdr, nil, &logic.NoHeaderLedger{})
			require.NoError(b, err)
		}
	})

}
