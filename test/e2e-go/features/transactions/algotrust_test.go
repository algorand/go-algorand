package transactions

import (
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	datatransactions "github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func TestAlgotrust(t *testing.T) {
	//testAlgoTrust(true, t)
	testAlgoTrust(false, t)
}

func testAlgoTrust(useAlgoTrust bool, t *testing.T) {

	bads := 10
	var fixture fixtures.RestClientFixture
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "AlgoTrust.json"))
	r := require.New(fixtures.SynchronizedTest(t))

	// get online and offline accounts
	relayAccount := getFirstAccountFromNamedNode(&fixture, r, "Relay")
	relayClient := fixture.GetLibGoalClientForNamedNode("Relay")
	honestAccount := getFirstAccountFromNamedNode(&fixture, r, "Honest")
	honestClient := fixture.GetLibGoalClientForNamedNode("Honest")

	badAccounts := make([]string, bads, bads)
	badClients := make([]libgoal.Client, bads, bads)
	badControllers := make([]nodecontrol.NodeController, bads, bads)

	for x := 0; x < bads; x++ {
		var err error
		name := fmt.Sprintf("Bad%d", x+1)
		badAccounts[x] = getFirstAccountFromNamedNode(&fixture, r, name)
		badClients[x] = fixture.GetLibGoalClientForNamedNode(name)
		badControllers[x], err = fixture.GetNodeController(name)
		r.NoError(err)

	}

	for x := 0; x < bads; x++ {
		cfg, err := config.LoadConfigFromDisk(badControllers[x].GetDataDir())
		r.NoError(err)
		cfg.MakeBadNode = true
		cfg.SaveToDisk(badControllers[x].GetDataDir())
	}

	relayController, err := fixture.GetNodeController("Relay")
	r.NoError(err)
	honestController, err := fixture.GetNodeController("Honest")
	r.NoError(err)

	{
		cfg, err := config.LoadConfigFromDisk(relayController.GetDataDir())
		r.NoError(err)
		cfg.MakeBadNode = false
		cfg.AlgoTrust = useAlgoTrust
		cfg.SaveToDisk(relayController.GetDataDir())

		cfg, err = config.LoadConfigFromDisk(honestController.GetDataDir())
		r.NoError(err)
		cfg.MakeBadNode = false
		cfg.AlgoTrust = useAlgoTrust
		cfg.SaveToDisk(honestController.GetDataDir())
	}

	fixture.Start()
	defer fixture.Shutdown()

	// learn initial balances
	initialRound := uint64(1)
	r.NoError(fixture.WaitForRoundWithTimeout(initialRound))
	initialBalance, _ := honestClient.GetBalance(honestAccount)
	fmt.Println(initialBalance)

	minFee, _, err := fixture.MinFeeAndBalance(initialRound)
	r.NoError(err)

	//	_, err = honestClient.SendPaymentFromUnencryptedWallet(honestAccount, relayAccount, minFee, 0, nil)
	//	require.NoError(t, err)

	wg := sync.WaitGroup{}
	ctx, ctxCancel := context.WithCancel(context.Background())
	wg.Add(12)
	go func() {
		defer wg.Done()
		for {
			currentRound, err := relayClient.CurrentRound()
			r.NoError(err)
			if currentRound > 300 {
				ctxCancel()
				return
			}
			time.Sleep(4 * time.Second)
		}
	}()
	go sendTransactions(&wg, ctx, true, honestAccount, relayAccount, 0, minFee, honestClient, &fixture, t)
	for x := 0; x < bads; x++ {
		go sendTransactions(&wg, ctx, false, badAccounts[x], relayAccount, 1000000000, minFee, badClients[x], &fixture, t)
	}
	wg.Wait()

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

func sendTransactions(wg *sync.WaitGroup, ctx context.Context, wait bool, account, account2 string, amt, minFee uint64, client libgoal.Client, fixture *fixtures.RestClientFixture, t *testing.T) {
	defer wg.Done()
	tcounter := 0
	points := uint64(1)
	var tx datatransactions.Transaction
	var err error
	for x := 0; x < 1000000; x++ {

		expPoints := points
		for points > uint64(0) {
			select {
			case <-ctx.Done():
				return
			default:
			}
			note := make([]byte, binary.MaxVarintLen64)
			binary.PutUvarint(note, uint64(tcounter))
			tcounter++

			if tcounter%200 == 0 {
				fmt.Printf("\r%d / %d", tcounter, 1000000)
			}

			tx, err = client.SendPaymentFromUnencryptedWallet(account, account2, minFee, amt, note)
			if err != nil {
				fmt.Println(x, err)
				time.Sleep(1000 * time.Millisecond)
				continue
			}
			require.NoError(t, err)
			points = points - 1
		}
		if wait {
			status, err := client.Status()
			require.NoError(t, err)
			_, err = fixture.WaitForConfirmedTxn(status.LastRound+200, account, tx.ID().String())
			require.NoError(t, err)
		}
		points = expPoints * 2
	}

}
