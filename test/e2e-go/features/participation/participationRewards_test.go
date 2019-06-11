// Copyright (C) 2019 Algorand, Inc.
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

package participation

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func getFirstAccountFromNamedNode(fixture fixtures.RestClientFixture, r *require.Assertions, nodeName string) (account string) {
	cli := fixture.GetLibGoalClientForNamedNode(nodeName)
	wh, err := cli.GetUnencryptedWalletHandle()
	r.NoError(err)
	onlineAccountList, _ := cli.ListAddresses(wh)
	r.True(len(onlineAccountList) > 0)
	account = onlineAccountList[0]
	return
}

func waitUntilRewards(t *testing.T, fixture *fixtures.RestClientFixture, round uint64) (uint64, error) {
	block, err := fixture.AlgodClient.Block(round)
	require.NoError(t, err)

	for {
		round++
		err := fixture.WaitForRoundWithTimeout(round + 1)
		require.NoError(t, err)
		nextBlock, err := fixture.AlgodClient.Block(round)
		require.NoError(t, err)

		if nextBlock.RewardsLevel > block.RewardsLevel {
			// reward level increased, rewards were granted
			return round, nil
		}
		if nextBlock.RewardsResidue == block.RewardsResidue {
			// we're stuck
			return round, fmt.Errorf("does not accrue rewards, residue stuck on %v", block.RewardsResidue)
		}
		block = nextBlock
	}
}

func spendToNonParticipating(t *testing.T, fixture *fixtures.RestClientFixture, lastRound uint64, account string, balance uint64, minFee uint64) uint64 {
	// move a lot of Algos to a non participating account -- the incentive pool
	poolAddr := basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff} // hardcoded; change if the pool address changes
	pd := poolAddr.GetChecksumAddress()
	drainTx, err := fixture.LibGoalClient.SendPaymentFromUnencryptedWallet(account, pd.String(), minFee, balance-balance/100-minFee, nil)
	require.NoError(t, err)
	fixture.WaitForAllTxnsToConfirm(lastRound+uint64(10), map[string]string{drainTx.ID().String(): account})
	return balance / 100
}

func TestOnlineOfflineRewards(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "FourNodes.json"))
	defer fixture.Shutdown()

	// get online and offline accounts
	onlineAccount := getFirstAccountFromNamedNode(fixture, r, "Online")
	onlineClient := fixture.GetLibGoalClientForNamedNode("Online")
	offlineAccount := getFirstAccountFromNamedNode(fixture, r, "Offline")
	offlineClient := fixture.GetLibGoalClientForNamedNode("Offline")

	// learn initial balances
	initialRound := uint64(301)
	r.NoError(fixture.WaitForRoundWithTimeout(initialRound))
	initialOnlineBalance, _ := onlineClient.GetBalance(onlineAccount)
	initialOfflineBalance, _ := offlineClient.GetBalance(offlineAccount)

	minFee, _, err := fixture.MinFeeAndBalance(initialRound)
	r.NoError(err)

	// move a lot of Algos to a non participating account so we accrue rewards faster
	initialOnlineBalance = spendToNonParticipating(t, &fixture, initialRound, onlineAccount, initialOnlineBalance, minFee)

	// accrue rewards by letting time pass
	rewardRound, err := waitUntilRewards(t, &fixture, initialRound)
	r.NoError(fixture.WaitForRoundWithTimeout(rewardRound))
	// do a balance poke by moving funds b/w accounts. this will cause balances to reflect received rewards
	pokeAmount := uint64(1)
	txidsAndAddresses := make(map[string]string)
	tx1, err := onlineClient.SendPaymentFromUnencryptedWallet(onlineAccount, offlineAccount, minFee, pokeAmount, nil)
	txidsAndAddresses[tx1.ID().String()] = onlineAccount
	r.NoError(err)
	tx2, err := offlineClient.SendPaymentFromUnencryptedWallet(offlineAccount, onlineAccount, minFee, pokeAmount, nil)
	txidsAndAddresses[tx2.ID().String()] = offlineAccount
	r.NoError(err)
	fixture.WaitForAllTxnsToConfirm(rewardRound+uint64(10), txidsAndAddresses)
	// make sure the nodes agree on current round
	status, err := onlineClient.Status()
	r.NoError(err)
	_, err = offlineClient.WaitForRound(status.LastRound)

	finalOnlineBalance, _ := onlineClient.GetBalance(onlineAccount)
	finalOfflineBalance, _ := offlineClient.GetBalance(offlineAccount)

	blk, err := fixture.AlgodClient.Block(initialRound)
	r.NoError(err)
	rewardUnit := config.Consensus[protocol.ConsensusVersion(blk.CurrentProtocol)].RewardUnit
	// online account should be rewarded at least the expected amount
	r.True(initialOnlineBalance+initialOnlineBalance/rewardUnit-minFee <= finalOnlineBalance, "onlineAccount started with %d and ended with %d.", initialOnlineBalance, finalOnlineBalance)
	// offline account should be rewarded at least the expected amount
	r.True(initialOfflineBalance+initialOfflineBalance/rewardUnit-minFee <= finalOfflineBalance, "offlineAccount started with %d and ended with %d", initialOfflineBalance, finalOfflineBalance)
}

func TestPartkeyOnlyRewards(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "FourNodes.json"))
	defer fixture.Shutdown()

	// get partkey only accounts
	richAccount, _ := fixture.GetRichestAccount()
	client := fixture.GetLibGoalClientForNamedNode("Partkey")
	accounts := fixture.GetParticipationOnlyAccounts(client)
	account := accounts[0].Address().GetChecksumAddress()

	status, err := fixture.LibGoalClient.Status()
	r.NoError(err)

	// learn initial balances
	r.NoError(fixture.WaitForRoundWithTimeout(status.LastRound))
	initialBalance, err := client.GetBalance(account.String())
	r.NoError(err)
	// accrue rewards by letting time pass
	arbitraryPostGenesisRound := uint64(316)
	r.NoError(fixture.WaitForRoundWithTimeout(arbitraryPostGenesisRound))

	// move a lot of Algos to a non participating account so we accrue rewards faster
	minFee, minBalance, err := fixture.MinFeeAndBalance(status.LastRound)
	r.NoError(err)
	spendToNonParticipating(t, &fixture, status.LastRound, richAccount.Address, richAccount.Amount, minFee)

	rewardRound, err := waitUntilRewards(t, &fixture, status.LastRound)
	r.NoError(fixture.WaitForRoundWithTimeout(rewardRound))

	// do a balance poke by moving funds b/w accounts. this will cause balances to reflect received rewards
	tx, err := fixture.LibGoalClient.SendPaymentFromUnencryptedWallet(richAccount.Address, account.String(), minFee, minBalance, nil)
	r.NoError(err)
	fixture.WaitForTxnConfirmation(arbitraryPostGenesisRound+uint64(10), tx.ID().String(), richAccount.Address)
	finalBalance, err := client.GetBalance(account.String())
	r.NoError(err)
	delta := finalBalance - initialBalance
	r.True(delta > minBalance, "partkey only account should get rewards: started with %d and ended with %d for a delta of %d (considering the %d poke-payment)", initialBalance, finalBalance, delta, minBalance)
}

func TestRewardUnitThreshold(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "FourNodes.json"))
	defer fixture.Shutdown()

	// get "poor" account (has 1% stake as opposed to 33%)
	poorAccount := getFirstAccountFromNamedNode(fixture, r, "SmallNode")
	client := fixture.GetLibGoalClientForNamedNode("SmallNode")
	// make new account
	wh, _ := client.GetUnencryptedWalletHandle()
	newAccount, _ := client.GenerateAddress(wh)
	// learn initial balances

	initialFixtureStatus, err := fixture.LibGoalClient.Status()
	r.NoError(err)
	initialRound := initialFixtureStatus.LastRound
	_, err = client.WaitForRound(initialRound)
	r.NoError(err)
	r.NoError(fixture.WaitForRoundWithTimeout(initialRound))
	initialBalancePoorAccount, _ := client.GetBalance(poorAccount)
	initialBalanceNewAccount, _ := client.GetBalance(newAccount)

	minFee, minBalance, err := fixture.MinFeeAndBalance(initialRound)
	r.NoError(err)
	blk, err := client.Block(initialRound)
	r.NoError(err)
	rewardUnit := config.Consensus[protocol.ConsensusVersion(blk.CurrentProtocol)].RewardUnit
	// accrue rewards by letting time pass

	txnFee := minFee
	richAccount, _ := fixture.GetRichestAccount()

	// move a lot of Algos to a non participating account so we accrue rewards faster
	spendToNonParticipating(t, &fixture, initialRound, richAccount.Address, richAccount.Amount, minFee)

	amountRichAccountPokesWith := uint64(1)
	lessThanRewardUnit, overflow := basics.OSub(rewardUnit, amountRichAccountPokesWith)
	r.False(overflow)
	r.True(lessThanRewardUnit >= minBalance, "change this test to have a new account with X reward units and compute its rewards")

	tx, err := fixture.LibGoalClient.SendPaymentFromUnencryptedWallet(richAccount.Address, newAccount, txnFee, lessThanRewardUnit, nil)
	r.NoError(err)
	fixture.WaitForAllTxnsToConfirm(initialRound+uint64(10), map[string]string{tx.ID().String(): richAccount.Address})

	// wait for the client node to catch up to the same round as the fixture node
	fixtureStatus, _ := fixture.LibGoalClient.Status()
	_, err = client.WaitForRound(fixtureStatus.LastRound)
	r.NoError(err)
	// at this point, the new account has just a little bit less than what it needs to get rewards, make sure it doesn't
	curStatus, _ := client.Status()
	rewardRound, err := waitUntilRewards(t, &fixture, initialRound)
	r.NoError(err)
	client.WaitForRound(rewardRound)

	txidsAndAddresses := make(map[string]string)
	tx1, err := fixture.LibGoalClient.SendPaymentFromUnencryptedWallet(richAccount.Address, poorAccount, txnFee, amountRichAccountPokesWith, nil)
	txidsAndAddresses[tx1.ID().String()] = richAccount.Address
	r.NoError(err)
	tx2, err := fixture.LibGoalClient.SendPaymentFromUnencryptedWallet(richAccount.Address, newAccount, txnFee, amountRichAccountPokesWith, nil)
	r.NoError(err)
	txidsAndAddresses[tx2.ID().String()] = richAccount.Address
	fixture.WaitForAllTxnsToConfirm(rewardRound+uint64(10), txidsAndAddresses)

	// wait for the client node to catch up to the same round as the fixture node
	fixtureStatus, _ = fixture.LibGoalClient.Status()
	_, err = client.WaitForRound(fixtureStatus.LastRound)
	r.NoError(err)
	// newAccount should NOT be rewarded
	// poorAccount should be rewarded
	updatedBalancePoorAccount, _ := client.AccountInformation(poorAccount)
	updatedBalanceNewAccount, _ := client.AccountInformation(newAccount)
	poorAccountDelta := updatedBalancePoorAccount.Amount - initialBalancePoorAccount
	r.True(amountRichAccountPokesWith+initialBalancePoorAccount/rewardUnit <= poorAccountDelta, "non-empty account with balance > rewardunit (%d) should accrue rewards. started with %d, given %d, now has %d", rewardUnit, initialBalancePoorAccount, amountRichAccountPokesWith, updatedBalancePoorAccount.Amount)
	r.True(initialBalancePoorAccount/rewardUnit <= updatedBalancePoorAccount.Rewards, "non-empty account with balance > rewardunit (%d) should accrue rewards. started with %d, given %d, now has %d, actual rewards %d", rewardUnit, initialBalancePoorAccount, amountRichAccountPokesWith, updatedBalancePoorAccount.Amount, updatedBalancePoorAccount.Rewards)

	newAccountDelta := updatedBalanceNewAccount.Amount - initialBalanceNewAccount
	r.Equal(newAccountDelta, updatedBalanceNewAccount.Amount, "empty account should have accrued no rewards")
	// move 1 config.Protocol.RewardUnit to new account, wait for txn to confirm

	// after the last poke, the new account should have enough stake to get rewards.
	curStatus, _ = fixture.AlgodClient.Status()
	rewardRound2, err := waitUntilRewards(t, &fixture, curStatus.LastRound)
	r.NoError(err)
	client.WaitForRound(rewardRound2)

	// poke the new account again to trigger the computation
	tx3, err := fixture.LibGoalClient.SendPaymentFromUnencryptedWallet(richAccount.Address, newAccount, txnFee, amountRichAccountPokesWith, nil)
	txidsAndAddresses[tx3.ID().String()] = richAccount.Address
	curStatus, _ = client.Status()
	fixture.WaitForAllTxnsToConfirm(curStatus.LastRound+uint64(10), txidsAndAddresses)

	// wait for the client node to catch up to the same round as the fixture node
	fixtureStatus, _ = fixture.LibGoalClient.Status()
	_, err = client.WaitForRound(fixtureStatus.LastRound)
	r.NoError(err)

	latestBalanceNewAccount, _ := client.AccountInformation(newAccount)

	r.True((rewardUnit-1+2*amountRichAccountPokesWith)+(rewardUnit-1+amountRichAccountPokesWith)/rewardUnit <= latestBalanceNewAccount.Amount,
		"account sent at least %d should have accrued rewards. started with %d, was sent %d + 2* %d, so increase should be more than the %d seen",
		rewardUnit, initialBalanceNewAccount, rewardUnit-1, amountRichAccountPokesWith, rewardUnit+amountRichAccountPokesWith) // first value was 0xf4242 second value was 0xf4246, account earned 4 microAlgos too many?
	r.True((rewardUnit-1+amountRichAccountPokesWith)/rewardUnit <= latestBalanceNewAccount.Rewards, "The new account should have gained rewards as a result of funds transfer")
}

var defaultPoolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func TestRewardRateRecalculation(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each_RapidRewardRecalculation.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient
	r.NoError(fixture.WaitForRoundWithTimeout(uint64(5)))
	richAccount, err := fixture.GetRichestAccount()
	r.NoError(err)
	rewardsAccount := defaultPoolAddr.GetChecksumAddress().String()
	amountToSend := uint64(1e15) // 1e12 insufficient

	curStatus, err := client.Status()
	r.NoError(err)
	minFee, minBal, err := fixture.MinFeeAndBalance(curStatus.LastRound)
	r.NoError(err)
	deadline := curStatus.LastRound + uint64(5)
	fixture.SendMoneyAndWait(deadline, amountToSend, minFee, richAccount.Address, rewardsAccount)

	blk, err := client.Block(curStatus.LastRound)
	r.NoError(err)
	consensus := config.Consensus[protocol.ConsensusVersion(blk.CurrentProtocol)]
	rewardRecalcRound := consensus.RewardsRateRefreshInterval
	r.NoError(fixture.WaitForRoundWithTimeout(rewardRecalcRound - 1))
	balanceOfRewardsPool, roundQueried := fixture.GetBalanceAndRound(rewardsAccount)
	if roundQueried != rewardRecalcRound-1 {
		r.FailNow("got rewards pool balance on round %d but wanted the balance on round %d, failing out", rewardRecalcRound-1, roundQueried)
	}
	r.NoError(fixture.WaitForRoundWithTimeout(rewardRecalcRound))
	blk, err = client.Block(rewardRecalcRound)
	r.NoError(err)
	r.Equal((balanceOfRewardsPool-minBal)/consensus.RewardsRateRefreshInterval, blk.RewardsRate)

	curStatus, err = client.Status()
	r.NoError(err)
	deadline = curStatus.LastRound + uint64(5)
	fixture.SendMoneyAndWait(deadline, amountToSend, minFee, richAccount.Address, rewardsAccount)

	rewardRecalcRound = rewardRecalcRound + consensus.RewardsRateRefreshInterval

	r.NoError(fixture.WaitForRoundWithTimeout(rewardRecalcRound - 1))
	balanceOfRewardsPool, roundQueried = fixture.GetBalanceAndRound(rewardsAccount)
	if roundQueried != rewardRecalcRound-1 {
		r.FailNow("got rewards pool balance on round %d but wanted the balance on round %d, failing out", rewardRecalcRound-1, roundQueried)
	}
	r.NoError(fixture.WaitForRoundWithTimeout(rewardRecalcRound))
	blk, err = client.Block(rewardRecalcRound)
	r.NoError(err)
	r.Equal((balanceOfRewardsPool-minBal)/consensus.RewardsRateRefreshInterval, blk.RewardsRate)
	// if the network keeps progressing without error,
	// this shows the network is healthy and that we didn't panic
	finalRound := rewardRecalcRound + uint64(5)
	r.NoError(fixture.WaitForRoundWithTimeout(finalRound))
}
