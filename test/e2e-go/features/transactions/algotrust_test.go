package transactions

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func TestAlgotrust(t *testing.T) {

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "AlgoTrust.json"))
	defer fixture.Shutdown()
	r := require.New(fixtures.SynchronizedTest(t))

	// get online and offline accounts
	relayAccount := getFirstAccountFromNamedNode(&fixture, r, "Relay")
	//	relayClient := fixture.GetLibGoalClientForNamedNode("Relay")
	honestAccount := getFirstAccountFromNamedNode(&fixture, r, "Honest")
	honestClient := fixture.GetLibGoalClientForNamedNode("Honest")
	//	badOneAccount := getFirstAccountFromNamedNode(&fixture, r, "BadOne")
	//	badOneClient := fixture.GetLibGoalClientForNamedNode("BadOne")
	//	badTwoAccount := getFirstAccountFromNamedNode(&fixture, r, "BadTwo")
	//	badTwoClient := fixture.GetLibGoalClientForNamedNode("BadTwo")

	// learn initial balances
	initialRound := uint64(1)
	r.NoError(fixture.WaitForRoundWithTimeout(initialRound))
	initialBalance, _ := honestClient.GetBalance(honestAccount)
	fmt.Println(initialBalance)

	minFee, _, err := fixture.MinFeeAndBalance(initialRound)
	r.NoError(err)

	tx, err := honestClient.SendPaymentFromUnencryptedWallet(honestAccount, relayAccount, minFee, 0, nil)
	require.NoError(t, err)

	points := uint64(1)

	tcounter := 0
	for x := 0; x < 1000000; x++ {

		expPoints := points
		for points > uint64(0) {
			note := make([]byte, binary.MaxVarintLen64)
			binary.PutUvarint(note, uint64(tcounter))
			tcounter++

			if tcounter%100 == 0 {
				fmt.Printf("\r%d / %d", tcounter, 1000000)
				go func() {
					endingBalance, _ := honestClient.GetBalance(honestAccount)
					fmt.Println("xxxxx    ", initialBalance-endingBalance)
				}()
			}

			tx, err = honestClient.SendPaymentFromUnencryptedWallet(honestAccount, relayAccount, minFee, 0, note)
			if err != nil {
				fmt.Println(x, err)
				time.Sleep(1000 * time.Millisecond)
				continue
			}
			require.NoError(t, err)
			points = points - 1
		}
		status, err := honestClient.Status()
		require.NoError(t, err)
		_, err = fixture.WaitForConfirmedTxn(status.LastRound+20, honestAccount, tx.ID().String())
		require.NoError(t, err)
		points = expPoints * 2
	}

	fixture.WaitForConfirmedTxn(0+20, honestAccount, tx.ID().String())

	endingBalance, _ := honestClient.GetBalance(honestAccount)
	fmt.Println(initialBalance - endingBalance)
	fmt.Println(initialBalance)
	fmt.Println(endingBalance)
}

func getFirstAccountFromNamedNode(fixture *fixtures.RestClientFixture, r *require.Assertions, nodeName string) (account string) {
	cli := fixture.GetLibGoalClientForNamedNode(nodeName)
	wh, err := cli.GetUnencryptedWalletHandle()
	r.NoError(err)
	onlineAccountList, _ := cli.ListAddresses(wh)
	r.True(len(onlineAccountList) > 0)
	account = onlineAccountList[0]
	return
}
