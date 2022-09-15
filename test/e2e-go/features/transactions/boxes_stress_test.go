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

package transactions

import (
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	algodclient "github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	kmdclient "github.com/algorand/go-algorand/daemon/kmd/client"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// func checkEqual2(expected []string, actual []string) bool {
// 	if len(expected) != len(actual) {
// 		return false
// 	}
// 	for i, e := range expected {
// 		if e != actual[i] {
// 			return false
// 		}
// 	}
// 	return true
// }

const genericBoxProgram string = `#pragma version 8
txn ApplicationID
bz end

txn ApplicationArgs 0 		// box op instruction
byte "create"
==
bnz create

txn ApplicationArgs 0 		// box op instruction
byte "extract"
==
bnz extract

txn ApplicationArgs 0 		// box op instruction
byte "replace"
==
bnz replace

txn ApplicationArgs 0 		// box op instruction
byte "del"
==
bnz del

txn ApplicationArgs 0 		// box op instruction
byte "len"
==
bnz len

txn ApplicationArgs 0 		// box op instruction
byte "get"
==
bnz get

txn ApplicationArgs 0 		// box op instruction
byte "put"
==
bnz put

bad:
	err

// Box opcode handlers
create:
	txn ApplicationArgs 1
	txn ApplicationArgs 2
	btoi
	box_create
	itob	// 1 === actual_creation
	log
	b end

extract:
	b end
	txn ApplicationArgs 1
	txn ApplicationArgs 2
	btoi
	txn ApplicationArgs 3
	btoi
	box_extract
	b end

replace:
	txn ApplicationArgs 1
	txn ApplicationArgs 2
	btoi
	txn ApplicationArgs 3
	box_replace
	b end

del:
	txn ApplicationArgs 1
	box_del
	itob 	// 1 === actual_deletion
	log
	b end

len:
	txn ApplicationArgs 1
	box_len
	swap
	itob 	// length
	swap
	itob	// existed
	concat
	log
	b end

get:
	txn ApplicationArgs 1
	box_get
	itob	// existed
	concat
	log
	b end

put:
	txn ApplicationArgs 1
	txn ApplicationArgs 2
	box_put
	b end

end:
	int 1
`

const clearProgram string = `#pragma version 8
int 1
`

var errWaitForTransactionTimeout = errors.New("wait for transaction timed out")

func waitForTransaction(t *testing.T, testClient libgoal.Client, fromAddress, txID string, timeout time.Duration) (tx v1.Transaction, err error) {
	a := require.New(fixtures.SynchronizedTest(t))
	rnd, err := testClient.Status()
	a.NoError(err)
	if rnd.LastRound == 0 {
		t.Fatal("it is currently round 0 but we need to wait for a transaction that might happen this round but we'll never know if that happens because ConfirmedRound==0 is indestinguishable from not having happened")
	}
	timeoutTime := time.Now().Add(timeout)
	for {
		tx, err = testClient.TransactionInformation(fromAddress, txID)
		if err != nil && strings.HasPrefix(err.Error(), "HTTP 404") {
			tx, err = testClient.PendingTransactionInformation(txID)
		}
		if err == nil {
			a.NotEmpty(tx)
			a.Empty(tx.PoolError)
			if tx.ConfirmedRound > 0 {
				return
			}
		}
		if time.Now().After(timeoutTime) {
			err = errWaitForTransactionTimeout
			return
		}
		time.Sleep(time.Second)
	}
}

func getMaxBalAddr(t *testing.T, testClient libgoal.Client, addresses []string) (someBal uint64, someAddress string) {
	a := require.New(fixtures.SynchronizedTest(t))
	someBal = 0
	for _, addr := range addresses {
		bal, err := testClient.GetBalance(addr)
		a.NoError(err)
		if bal > someBal {
			someAddress = addr
			someBal = bal
		}
	}
	return
}

func operateBoxAndSendTxn(t *testing.T, a *require.Assertions, testClient libgoal.Client, operation string, createdAppID basics.AppIndex, someAddress string, boxNames []string, boxValues []string) {
	txns := make([]transactions.Transaction, len(boxNames))
	txIDs := make(map[string]string, len(boxNames))

	var err error

	for i := 0; i < len(boxNames); i++ {
		appArgs := [][]byte{
			[]byte(operation),
			[]byte(boxNames[i]),
			[]byte(boxValues[i]),
		}
		boxRef := transactions.BoxRef{
			Name:  []byte(boxNames[i]),
			Index: 0,
		}

		txns[i], err = testClient.MakeUnsignedAppNoOpTx(
			uint64(createdAppID), appArgs,
			nil, nil, nil,
			[]transactions.BoxRef{boxRef},
		)
		a.NoError(err)
		txns[i], err = testClient.FillUnsignedTxTemplate(someAddress, 0, 0, 0, txns[i])
		a.NoError(err)
		txIDs[txns[i].ID().String()] = someAddress
	}

	var gid crypto.Digest
	gid, err = testClient.GroupID(txns)
	a.NoError(err)

	stxns := make([]transactions.SignedTxn, len(boxNames))
	for i := 0; i < len(boxNames); i++ {
		txns[i].Group = gid
		wh, err := testClient.GetUnencryptedWalletHandle()
		a.NoError(err)
		stxns[i], err = testClient.SignTransactionWithWallet(wh, nil, txns[i])
		a.NoError(err)
	}

	err = testClient.BroadcastTransactionGroup(stxns)
	a.NoError(err)

	_, err = waitForTransaction(t, testClient, someAddress, txns[0].ID().String(), 30*time.Second)
	a.NoError(err)
}

func operateAndMatchRes(a *require.Assertions, t *testing.T, testClient libgoal.Client, createdAppID basics.AppIndex, someAddress string, operation string, boxNames []string) {
	createdBoxName := map[string]bool{}
	var createdBoxCount uint64

	boxValues := make([]string, len(boxNames))
	if operation == "create" {
		for i, box := range boxNames {
			keyValid, ok := createdBoxName[box]
			a.False(ok && keyValid)
			boxValues[i] = ""
		}
	} else if operation == "delete" {
		for i, box := range boxNames {
			keyValid, ok := createdBoxName[box]
			a.True(keyValid == ok)
			boxValues[i] = ""
		}
	} else {
		a.True(false)
	}

	operateBoxAndSendTxn(t, a, testClient, operation, createdAppID, someAddress, boxNames, boxValues)

	if operation == "create" {
		for _, box := range boxNames {
			createdBoxName[box] = true
		}
		createdBoxCount += uint64(len(boxNames))
	} else if operation == "delete" {
		for _, box := range boxNames {
			createdBoxName[box] = false
		}
		createdBoxCount -= uint64(len(boxNames))
	}

	var resp generated.BoxesResponse
	resp, err := testClient.ApplicationBoxes(uint64(createdAppID), 0)
	a.NoError(err)
	a.Equal(createdBoxCount, uint64(len(resp.Boxes)))
	for _, b := range resp.Boxes {
		a.True(createdBoxName[string(b.Name)])
	}
}

func TestBoxesStress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	testClient.WaitForRound(1)

	testClient.SetAPIVersionAffinity(algodclient.APIVersionV2, kmdclient.APIVersionV1)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := getMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	ops, err := logic.AssembleString(genericBoxProgram)
	a.NoError(err)
	approval := ops.Program

	ops, err = logic.AssembleString(clearProgram)
	a.NoError(err)
	clearState := ops.Program

	gl := basics.StateSchema{}
	lc := basics.StateSchema{}

	// create app
	appCreateTxn, err := testClient.MakeUnsignedApplicationCallTx(
		0, nil, nil, nil,
		nil, nil, transactions.NoOpOC,
		approval, clearState, gl, lc, 0,
	)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(someAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)
	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	_, err = waitForTransaction(t, testClient, someAddress, appCreateTxID, 30*time.Second)
	a.NoError(err)

	// get app ID
	submittedAppCreateTxn, err := testClient.PendingTransactionInformationV2(appCreateTxID)
	a.NoError(err)
	a.NotNil(submittedAppCreateTxn.ApplicationIndex)
	createdAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)
	a.Greater(uint64(createdAppID), uint64(0))

	// fund app account
	appFundTxn, err := testClient.SendPaymentFromWallet(
		wh, nil, someAddress, createdAppID.Address().String(),
		0, 10_000_000, nil, "", 0, 0,
	)
	a.NoError(err)
	appFundTxID := appFundTxn.ID()
	_, err = waitForTransaction(t, testClient, someAddress, appFundTxID.String(), 30*time.Second)
	a.NoError(err)

	testingBoxNames := []string{
		` `,
		`     	`,
		` ? = % ;`,
		`; DROP *;`,
		`OR 1 = 1;`,
		`"      ;  SELECT * FROM kvstore; DROP acctrounds; `,
		`背负青天而莫之夭阏者，而后乃今将图南。`,
		`於浩歌狂熱之際中寒﹔於天上看見深淵。`,
		`於一切眼中看見無所有﹔於無所希望中得救。`,
		`有一遊魂，化為長蛇，口有毒牙。`,
		`不以嚙人，自嚙其身，終以殞顛。`,
		`那些智力超常的人啊`,
		`认为已经，熟悉了云和闪电的脾气`,
		`就不再迷惑，就不必了解自己，世界和他人`,
		`每天只管，被微风吹拂，与猛虎谈情`,
		`他们从来，不需要楼梯，只有窗口`,
		`把一切交付于梦境，和优美的浪潮`,
		`在这颗行星所有的酒馆，青春自由似乎理所应得`,
		`面向涣散的未来，只唱情歌，看不到坦克`,
		`在科学和啤酒都不能安抚的夜晚`,
		`他们丢失了四季，惶惑之行开始`,
		`这颗行星所有的酒馆，无法听到远方的呼喊`,
		`野心勃勃的灯火，瞬间吞没黑暗的脸庞`,
		`b64:APj/AA==`,
		`str:123.3/aa\\0`,
		string([]byte{0, 255, 254, 254}),
		string([]byte{0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF}),
		`; SELECT key from kvstore WHERE key LIKE %;`,
		`?&%!=`,
		"SELECT * FROM kvstore " + string([]byte{0, 0}) + " WHERE key LIKE %; ",
		string([]byte{'%', 'a', 'b', 'c', 0, 0, '%', 'a', '!'}),
		`
`,
		`™£´´∂ƒ∂ƒßƒ©∑®ƒß∂†¬∆`,
		`∑´´˙©˚¬∆ßåƒ√¬`,
	}

	resp, err := testClient.ApplicationBoxes(uint64(createdAppID), 0)
	a.NoError(err)
	a.Empty(resp.Boxes)

	for i := 0; i < len(testingBoxNames); i += 16 {
		var strSliceTest []string
		// grouping box names to operate, and create such boxes
		if i+16 >= len(testingBoxNames) {
			strSliceTest = testingBoxNames[i:]
		} else {
			strSliceTest = testingBoxNames[i : i+16]
		}
		operateAndMatchRes(a, t, testClient, createdAppID, someAddress, "create", strSliceTest)
	}

	maxBoxNumToGet := uint64(10)
	resp, err = testClient.ApplicationBoxes(uint64(createdAppID), maxBoxNumToGet)
	a.NoError(err)
	a.Len(resp.Boxes, int(maxBoxNumToGet))

	for i := 0; i < len(testingBoxNames); i += 16 {
		var strSliceTest []string
		// grouping box names to operate, and delete such boxes
		if i+16 >= len(testingBoxNames) {
			strSliceTest = testingBoxNames[i:]
		} else {
			strSliceTest = testingBoxNames[i : i+16]
		}
		operateAndMatchRes(a, t, testClient, createdAppID, someAddress, "delete", strSliceTest)
	}

	resp, err = testClient.ApplicationBoxes(uint64(createdAppID), 0)
	a.NoError(err)
	a.Empty(resp.Boxes)

	// Get Box value from box name
	encodeInt := func(n uint64) []byte {
		ibytes := make([]byte, 8)
		binary.BigEndian.PutUint64(ibytes, n)
		return ibytes
	}

	boxTests := [][]interface{}{
		{[]byte("foo"), "str:foo", []byte("bar12")},
		{encodeInt(12321), "int:12321", []byte{0, 1, 254, 3, 2}},
		{[]byte{0, 248, 255, 32}, "b64:APj/IA==", []byte("lux56")},
	}
	for _, boxTest := range boxTests {
		boxName := boxTest[0].([]byte)
		encodedName := boxTest[1].(string)
		// Box values are 5 bytes, as defined by the test TEAL program.
		boxValue := boxTest[2].([]byte)
		operateBoxAndSendTxn(t, a, testClient, "create", createdAppID, someAddress, []string{string(boxName)}, []string{""})
		operateBoxAndSendTxn(t, a, testClient, "set", createdAppID, someAddress, []string{string(boxName)}, []string{string(boxValue)})

		boxResponse, err := testClient.GetApplicationBoxByName(uint64(createdAppID), encodedName)
		a.NoError(err)
		a.Equal(boxName, boxResponse.Name)
		a.Equal(boxValue, boxResponse.Value)
	}
}
