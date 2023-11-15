// Copyright (C) 2019-2023 Algorand, Inc.
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

package other

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"

	helper "github.com/algorand/go-algorand/test/e2e-go/restAPI"
)

func TestPendingTransactionInfoInnerTxnAssetCreate(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	testClient.WaitForRound(1)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	prog := `#pragma version 5
txn ApplicationID
bz end
itxn_begin
int acfg
itxn_field TypeEnum
int 1000000
itxn_field ConfigAssetTotal
int 3
itxn_field ConfigAssetDecimals
byte "oz"
itxn_field ConfigAssetUnitName
byte "Gold"
itxn_field ConfigAssetName
byte "https://gold.rush/"
itxn_field ConfigAssetURL
byte 0x67f0cd61653bd34316160bc3f5cd3763c85b114d50d38e1f4e72c3b994411e7b
itxn_field ConfigAssetMetadataHash
itxn_submit
end:
int 1
return
`
	ops, err := logic.AssembleString(prog)
	a.NoError(err)
	approv := ops.Program
	ops, err = logic.AssembleString("#pragma version 5 \nint 1")
	clst := ops.Program
	a.NoError(err)

	gl := basics.StateSchema{}
	lc := basics.StateSchema{}

	// create app
	appCreateTxn, err := testClient.MakeUnsignedApplicationCallTx(0, nil, nil, nil, nil, nil, transactions.NoOpOC, approv, clst, gl, lc, 0)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(someAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)
	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	_, err = helper.WaitForTransaction(t, testClient, appCreateTxID, 30*time.Second)
	a.NoError(err)

	// get app ID
	submittedAppCreateTxn, err := testClient.PendingTransactionInformation(appCreateTxID)
	a.NoError(err)
	a.NotNil(submittedAppCreateTxn.ApplicationIndex)
	createdAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)
	a.NotZero(createdAppID)

	// fund app account
	appFundTxn, err := testClient.SendPaymentFromWallet(wh, nil, someAddress, createdAppID.Address().String(), 0, 1_000_000, nil, "", 0, 0)
	a.NoError(err)
	appFundTxID := appFundTxn.ID()
	_, err = helper.WaitForTransaction(t, testClient, appFundTxID.String(), 30*time.Second)
	a.NoError(err)

	// call app, which will issue an ASA create inner txn
	appCallTxn, err := testClient.MakeUnsignedAppNoOpTx(uint64(createdAppID), nil, nil, nil, nil, nil)
	a.NoError(err)
	appCallTxn, err = testClient.FillUnsignedTxTemplate(someAddress, 0, 0, 0, appCallTxn)
	a.NoError(err)
	appCallTxnTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCallTxn)
	a.NoError(err)
	_, err = helper.WaitForTransaction(t, testClient, appCallTxnTxID, 30*time.Second)
	a.NoError(err)

	// verify pending txn info of outer txn
	submittedAppCallTxn, err := testClient.PendingTransactionInformation(appCallTxnTxID)
	a.NoError(err)
	a.Nil(submittedAppCallTxn.ApplicationIndex)
	a.Nil(submittedAppCallTxn.AssetIndex)
	a.NotNil(submittedAppCallTxn.InnerTxns)
	a.Len(*submittedAppCallTxn.InnerTxns, 1)

	// verify pending txn info of inner txn
	innerTxn := (*submittedAppCallTxn.InnerTxns)[0]
	a.Nil(innerTxn.ApplicationIndex)
	a.NotNil(innerTxn.AssetIndex)
	createdAssetID := *innerTxn.AssetIndex
	a.NotZero(createdAssetID)

	createdAssetInfo, err := testClient.AssetInformation(createdAssetID)
	a.NoError(err)
	a.Equal(createdAssetID, createdAssetInfo.Index)
	a.Equal(createdAppID.Address().String(), createdAssetInfo.Params.Creator)
	a.Equal(uint64(1000000), createdAssetInfo.Params.Total)
	a.Equal(uint64(3), createdAssetInfo.Params.Decimals)
	a.Equal("oz", *createdAssetInfo.Params.UnitName)
	a.Equal("Gold", *createdAssetInfo.Params.Name)
	a.Equal("https://gold.rush/", *createdAssetInfo.Params.Url)
	expectedMetadata, err := hex.DecodeString("67f0cd61653bd34316160bc3f5cd3763c85b114d50d38e1f4e72c3b994411e7b")
	a.NoError(err)
	a.Equal(expectedMetadata, *createdAssetInfo.Params.MetadataHash)
}

func TestBoxNamesByAppID(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	testClient.WaitForRound(1)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	prog := `#pragma version 8
    txn ApplicationID
    bz end					// create the app
	txn NumAppArgs
	bz end					// approve when no app args
    txn ApplicationArgs 0   // [arg[0]] // fails if no args && app already exists
    byte "create"           // [arg[0], "create"] // create box named arg[1]
    ==                      // [arg[0]=?="create"]
    bz del                  // "create" ? continue : goto del
    int 5                   // [5]
    txn ApplicationArgs 1   // [5, arg[1]]
    swap
    box_create              // [] // boxes: arg[1] -> [5]byte
    assert
    b end
del:                        // delete box arg[1]
    txn ApplicationArgs 0   // [arg[0]]
    byte "delete"           // [arg[0], "delete"]
    ==                      // [arg[0]=?="delete"]
	bz set                  // "delete" ? continue : goto set
    txn ApplicationArgs 1   // [arg[1]]
    box_del                 // del boxes[arg[1]]
    assert
    b end
set:						// put arg[1] at start of box arg[0] ... so actually a _partial_ "set"
    txn ApplicationArgs 0   // [arg[0]]
    byte "set"              // [arg[0], "set"]
    ==                      // [arg[0]=?="set"]
    bz bad                  // "delete" ? continue : goto bad
    txn ApplicationArgs 1   // [arg[1]]
    int 0                   // [arg[1], 0]
    txn ApplicationArgs 2   // [arg[1], 0, arg[2]]
    box_replace             // [] // boxes: arg[1] -> replace(boxes[arg[1]], 0, arg[2])
    b end
bad:
    err
end:
    int 1
`
	ops, err := logic.AssembleString(prog)
	a.NoError(err)
	approval := ops.Program
	ops, err = logic.AssembleString("#pragma version 8\nint 1")
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
	_, err = helper.WaitForTransaction(t, testClient, appCreateTxID, 30*time.Second)
	a.NoError(err)

	// get app ID
	submittedAppCreateTxn, err := testClient.PendingTransactionInformation(appCreateTxID)
	a.NoError(err)
	a.NotNil(submittedAppCreateTxn.ApplicationIndex)
	createdAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)
	a.NotZero(createdAppID)

	// fund app account
	appFundTxn, err := testClient.SendPaymentFromWallet(
		wh, nil, someAddress, createdAppID.Address().String(),
		0, 10_000_000, nil, "", 0, 0,
	)
	a.NoError(err)
	appFundTxID := appFundTxn.ID()
	_, err = helper.WaitForTransaction(t, testClient, appFundTxID.String(), 30*time.Second)
	a.NoError(err)

	createdBoxName := map[string]bool{}
	var createdBoxCount uint64 = 0

	// define operate box helper
	operateBoxAndSendTxn := func(operation string, boxNames []string, boxValues []string, errPrefix ...string) {
		txns := make([]transactions.Transaction, len(boxNames))
		txIDs := make(map[string]string, len(boxNames))

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
			wh, err = testClient.GetUnencryptedWalletHandle()
			a.NoError(err)
			stxns[i], err = testClient.SignTransactionWithWallet(wh, nil, txns[i])
			a.NoError(err)
		}

		err = testClient.BroadcastTransactionGroup(stxns)
		if len(errPrefix) == 0 {
			a.NoError(err)
			_, err = helper.WaitForTransaction(t, testClient, txns[0].ID().String(), 30*time.Second)
			a.NoError(err)
		} else {
			a.ErrorContains(err, errPrefix[0])
		}
	}

	// `assertErrorResponse` confirms the _Result limit exceeded_ error response provides expected fields and values.
	assertErrorResponse := func(err error, expectedCount, requestedMax uint64) {
		a.Error(err)
		e := err.(client.HTTPError)
		a.Equal(400, e.StatusCode)

		var er *model.ErrorResponse
		err = protocol.DecodeJSON([]byte(e.ErrorString), &er)
		a.NoError(err)
		a.Equal("Result limit exceeded", er.Message)
		a.Equal(uint64(100000), ((*er.Data)["max-api-box-per-application"]).(uint64))
		a.Equal(requestedMax, ((*er.Data)["max"]).(uint64))
		a.Equal(expectedCount, ((*er.Data)["total-boxes"]).(uint64))

		a.Len(*er.Data, 3, fmt.Sprintf("error response (%v) contains unverified fields.  Extend test for new fields.", *er.Data))
	}

	// `assertBoxCount` sanity checks that the REST API respects `expectedCount` through different queries against app ID = `createdAppID`.
	assertBoxCount := func(expectedCount uint64) {
		// Query without client-side limit.
		resp, err := testClient.ApplicationBoxes(uint64(createdAppID), 0)
		a.NoError(err)
		a.Len(resp.Boxes, int(expectedCount))

		// Query with requested max < expected expectedCount.
		_, err = testClient.ApplicationBoxes(uint64(createdAppID), expectedCount-1)
		assertErrorResponse(err, expectedCount, expectedCount-1)

		// Query with requested max == expected expectedCount.
		resp, err = testClient.ApplicationBoxes(uint64(createdAppID), expectedCount)
		a.NoError(err)
		a.Len(resp.Boxes, int(expectedCount))

		// Query with requested max > expected expectedCount.
		resp, err = testClient.ApplicationBoxes(uint64(createdAppID), expectedCount+1)
		a.NoError(err)
		a.Len(resp.Boxes, int(expectedCount))
	}

	// helper function, take operation and a slice of box names
	// then submit transaction group containing all operations on box names
	// Then we check these boxes are appropriately created/deleted
	operateAndMatchRes := func(operation string, boxNames []string) {
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
			a.Failf("Unknown operation %s", operation)
		}

		operateBoxAndSendTxn(operation, boxNames, boxValues)

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

		var resp model.BoxesResponse
		resp, err = testClient.ApplicationBoxes(uint64(createdAppID), 0)
		a.NoError(err)

		expectedCreatedBoxes := make([]string, 0, createdBoxCount)
		for name, isCreate := range createdBoxName {
			if isCreate {
				expectedCreatedBoxes = append(expectedCreatedBoxes, name)
			}
		}
		sort.Strings(expectedCreatedBoxes)

		actualBoxes := make([]string, len(resp.Boxes))
		for i, box := range resp.Boxes {
			actualBoxes[i] = string(box.Name)
		}
		sort.Strings(actualBoxes)

		a.Equal(expectedCreatedBoxes, actualBoxes)
	}

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

	// Happy Vanilla paths:
	resp, err := testClient.ApplicationBoxes(uint64(createdAppID), 0)
	a.NoError(err)
	a.Empty(resp.Boxes)

	// Some Un-Happy / Non-Vanilla paths:

	// Even though the next box _does not exist_ as asserted by the error below,
	// querying it for boxes _DOES NOT ERROR_. There is no easy way to tell
	// the difference between non-existing boxes for an app that once existed
	// vs. an app the NEVER existed.
	nonexistantAppIndex := uint64(1337)
	_, err = testClient.ApplicationInformation(nonexistantAppIndex)
	a.ErrorContains(err, "application does not exist")
	resp, err = testClient.ApplicationBoxes(nonexistantAppIndex, 0)
	a.NoError(err)
	a.Len(resp.Boxes, 0)

	operateBoxAndSendTxn("create", []string{``}, []string{``}, "box names may not be zero length")

	for i := 0; i < len(testingBoxNames); i += 16 {
		var strSliceTest []string
		// grouping box names to operate, and create such boxes
		if i+16 >= len(testingBoxNames) {
			strSliceTest = testingBoxNames[i:]
		} else {
			strSliceTest = testingBoxNames[i : i+16]
		}
		operateAndMatchRes("create", strSliceTest)
	}

	assertBoxCount(uint64(len(testingBoxNames)))

	for i := 0; i < len(testingBoxNames); i += 16 {
		var strSliceTest []string
		// grouping box names to operate, and delete such boxes
		if i+16 >= len(testingBoxNames) {
			strSliceTest = testingBoxNames[i:]
		} else {
			strSliceTest = testingBoxNames[i : i+16]
		}
		operateAndMatchRes("delete", strSliceTest)
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

	boxTests := []struct {
		name        []byte
		encodedName string
		value       []byte
	}{
		{[]byte("foo"), "str:foo", []byte("bar12")},
		{encodeInt(12321), "int:12321", []byte{0, 1, 254, 3, 2}},
		{[]byte{0, 248, 255, 32}, "b64:APj/IA==", []byte("lux56")},
	}

	for _, boxTest := range boxTests {
		// Box values are 5 bytes, as defined by the test TEAL program.
		operateBoxAndSendTxn("create", []string{string(boxTest.name)}, []string{""})
		operateBoxAndSendTxn("set", []string{string(boxTest.name)}, []string{string(boxTest.value)})

		currentRoundBeforeBoxes, err := testClient.CurrentRound()
		a.NoError(err)
		boxResponse, err := testClient.GetApplicationBoxByName(uint64(createdAppID), boxTest.encodedName)
		a.NoError(err)
		currentRoundAfterBoxes, err := testClient.CurrentRound()
		a.NoError(err)
		a.Equal(boxTest.name, boxResponse.Name)
		a.Equal(boxTest.value, boxResponse.Value)
		// To reduce flakiness, only check the round from boxes is within a range.
		a.GreaterOrEqual(boxResponse.Round, currentRoundBeforeBoxes)
		a.LessOrEqual(boxResponse.Round, currentRoundAfterBoxes)
	}

	const numberOfBoxesRemaining = uint64(3)
	assertBoxCount(numberOfBoxesRemaining)

	// Non-vanilla. Wasteful but correct. Can delete an app without first cleaning up its boxes.
	appAccountData, err := testClient.AccountData(createdAppID.Address().String())
	a.NoError(err)
	a.Equal(numberOfBoxesRemaining, appAccountData.TotalBoxes)
	a.Equal(uint64(30), appAccountData.TotalBoxBytes)

	// delete the app
	appDeleteTxn, err := testClient.MakeUnsignedAppDeleteTx(uint64(createdAppID), nil, nil, nil, nil, nil)
	a.NoError(err)
	appDeleteTxn, err = testClient.FillUnsignedTxTemplate(someAddress, 0, 0, 0, appDeleteTxn)
	a.NoError(err)
	appDeleteTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appDeleteTxn)
	a.NoError(err)
	_, err = helper.WaitForTransaction(t, testClient, appDeleteTxID, 30*time.Second)
	a.NoError(err)

	_, err = testClient.ApplicationInformation(uint64(createdAppID))
	a.ErrorContains(err, "application does not exist")

	assertBoxCount(numberOfBoxesRemaining)
}
