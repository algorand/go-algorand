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

package auction

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/auction"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func detectAuctionCannotProceed(r *require.Assertions, params auction.Params, lastRound, pricePerAlgo uint64) {
	if lastRound+1 >= (params.FirstRound + params.PriceChunkRounds*params.NumChunks) {
		r.True(false, "Failing out - auction ended before bidding could even begin.")
	} else if pricePerAlgo == 0 {
		r.True(false, "Failing out - got a pricePerAlgo of 0.")
	}
}

func TestStartAndEndAuctionNoBids(t *testing.T) {
	t.Skip("Disabling since they need work and shouldn't block releases")
	if runtime.GOOS == "darwin" {
		t.Skip()
	}
	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	r := require.New(fixtures.SynchronizedTest(t))
	var fixture fixtures.AuctionFixture
	netTemplate := filepath.Join("nettemplates", "ThreeNodesEvenDist.json")
	auctionParamFile := filepath.Join("auctions", "AuctionParams_1.json")
	fixture.Setup(t, netTemplate)
	defer fixture.Shutdown()

	// start the auction
	_, params, _, _, err := fixture.StartAuction(auctionParamFile)
	r.NoError(err)
	// get the auction for inspection
	at, err := fixture.GetAuctionTracker()
	r.NoError(err)
	// wait for the last round of the auction to pass by
	// wait for ALL nodes to confirm last round has passed by
	lastRound := params.FirstRound + params.PriceChunkRounds*params.NumChunks
	r.NoError(fixture.WaitForRoundWithTimeout(lastRound + uint64(1)))
	otherClient1 := fixture.GetLibGoalClientForNamedNode("Node1")
	r.NoError(fixture.LibGoalFixture.ClientWaitForRoundWithTimeout(otherClient1, lastRound+uint64(1)))
	otherClient2 := fixture.GetLibGoalClientForNamedNode("Node2")
	r.NoError(fixture.LibGoalFixture.ClientWaitForRoundWithTimeout(otherClient2, lastRound+uint64(1)))

	// tell the running auction to settle up, and examine results
	auctionID, err := at.LastAuctionID()
	r.NoError(err)
	ra := at.Auctions[auctionID]
	bidOutcomes := ra.Settle(false)
	fixture.CrossVerifyEndOfAuction(params, bidOutcomes, false)
	// end the auction
	_, _, err = fixture.EndAuction()
	r.NoError(err)
}

func TestStartAndEndAuctionOneUserOneBid(t *testing.T) {
	t.Skip("Disabling since they need work and shouldn't block releases")
	if runtime.GOOS == "darwin" {
		t.Skip()
	}
	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	r := require.New(fixtures.SynchronizedTest(t))
	var fixture fixtures.AuctionFixture
	netTemplate := filepath.Join("nettemplates", "TwoNodes50Each.json")
	auctionParamFile := filepath.Join("auctions", "AuctionParams_1.json")
	fixture.Setup(t, netTemplate)
	defer fixture.Shutdown()

	// start the auction.
	_, _, _, _, err := fixture.StartAuction(auctionParamFile)
	r.NoError(err)
	// start tracking the auction.
	at, err := fixture.GetAuctionTracker()
	r.NoError(err)

	// get a wallet to bid with, and note its balance before the auction.
	wallets, _ := fixture.GetWalletsSortedByBalance()
	biddingAccount := wallets[0].Address
	initialBalance := wallets[0].Amount

	minTxnFee, _, err := fixture.CurrentMinFeeAndBalance()
	r.NoError(err)

	// build a bid and deposit. bidder spends all its currency at whatever current price.
	dollarsDeposited := 100
	centsDeposited := uint64(dollarsDeposited * 100)
	console := fixture.GetAuctionConsoleRestClient()
	bidID := uint64(0)
	// wait for the auction to be seen by the fixture.
	auctionID, err := fixture.WaitForNonZeroAuctionID()
	r.NoError(err)
	paramsResponse, err := fixture.GetAuctionConsoleRestClient().Params(auctionID.AuctionID)
	r.NoError(err)
	params := paramsResponse.Params
	fixture.WaitForRoundWithTimeout(params.FirstRound + uint64(1))
	auctionKey, err := fixture.GetAuctionMasterPublicKey()
	r.NoError(err)
	curStatus, _ := fixture.GetAlgodRestClient().Status()
	pricePerAlgo, err := console.CurrentPrice(auctionID.AuctionID, curStatus.LastRound)
	currencySpentOnBid := centsDeposited
	detectAuctionCannotProceed(r, params, curStatus.LastRound, pricePerAlgo.Price)
	_, _, err = fixture.MakeAndPostBidAndDeposit(bidID, auctionID.AuctionID, auctionKey, biddingAccount, pricePerAlgo.Price, currencySpentOnBid)
	r.NoError(err)
	// wait for the auction to end, then call auction-end script.
	fixture.WaitForRoundWithTimeout(params.FirstRound + params.PriceChunkRounds*params.NumChunks)
	_, _, err = fixture.EndAuction()
	r.NoError(err)
	// the auction-end script posts transactions. wait a round for them to clear.
	fixture.WaitForNextRound()
	// use the runningAuction object to verify correct auction end.
	ra := at.Auctions[auctionID.AuctionID]
	bidOutcomes := ra.Settle(false)
	fixture.CrossVerifyEndOfAuction(params, bidOutcomes, false)
	// confirm that algos were paid to the bidder's account.
	libGoalClient := fixture.GetLibGoalClient()
	actualBalanceResp, _ := libGoalClient.AccountInformation(biddingAccount)
	algosDesired := centsDeposited / pricePerAlgo.Price
	actualBalance := actualBalanceResp.Amount
	expectedBalance := initialBalance + uint64(algosDesired) - minTxnFee
	r.True(actualBalance > expectedBalance, "bidder started with %d algos, then tried to buy %d algos, so should have at least %d algos. instead, have %d algos", initialBalance, algosDesired, expectedBalance, actualBalance)
}

func TestStartAndEndAuctionOneUserTenBids(t *testing.T) {
	t.Skip("Disabling since they need work and shouldn't block releases")
	if runtime.GOOS == "darwin" {
		t.Skip()
	}
	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	r := require.New(fixtures.SynchronizedTest(t))
	var fixture fixtures.AuctionFixture
	netTemplate := filepath.Join("nettemplates", "TwoNodes50Each.json")
	auctionParamFile := filepath.Join("auctions", "AuctionParams_1.json")
	fixture.Setup(t, netTemplate)
	defer fixture.Shutdown()

	// start the auction.
	_, _, _, _, err := fixture.StartAuction(auctionParamFile)
	r.NoError(err)
	// start tracking the auction.
	at, err := fixture.GetAuctionTracker()
	r.NoError(err)
	// get a wallet to bid with, and note its balance before the auction.
	wallets, _ := fixture.GetWalletsSortedByBalance()
	biddingAccount := wallets[0].Address
	initialBalance := wallets[0].Amount
	// build bids. bidder spends all its currency at whatever current price, divided across numBids bids.
	dollarsDeposited := 100
	centsDeposited := uint64(dollarsDeposited * 100)
	console := fixture.GetAuctionConsoleRestClient()
	// wait for the auction to be seen by the fixture.
	auctionID, err := fixture.WaitForNonZeroAuctionID()
	r.NoError(err)

	paramsResponse, err := fixture.GetAuctionConsoleRestClient().Params(auctionID.AuctionID)
	r.NoError(err)
	params := paramsResponse.Params
	fixture.WaitForRoundWithTimeout(params.FirstRound + uint64(1))
	auctionKey, err := fixture.GetAuctionMasterPublicKey()
	r.NoError(err)
	curStatus, _ := fixture.GetAlgodRestClient().Status()
	pricePerAlgo, err := console.CurrentPrice(auctionID.AuctionID, curStatus.LastRound)
	detectAuctionCannotProceed(r, params, curStatus.LastRound, pricePerAlgo.Price)
	currencySpentOnAllBids := centsDeposited
	numBids := 10
	currencySpentOnEachBid := currencySpentOnAllBids / uint64(numBids)
	for i := 0; i < numBids; i++ {
		bidID := uint64(i)
		txid, _, err := fixture.MakeAndPostBidAndDeposit(bidID, auctionID.AuctionID, auctionKey, biddingAccount, pricePerAlgo.Price, currencySpentOnEachBid)
		r.NoError(err)
		fixture.AssertValidTxid(txid)
	}
	// wait for the auction to end, then call auction-end script.
	fixture.WaitForRoundWithTimeout(params.FirstRound + params.PriceChunkRounds*params.NumChunks)
	_, _, err = fixture.EndAuction()
	r.NoError(err)
	// the auction-end script posts transactions. wait a round for them to clear.
	fixture.WaitForNextRound()

	minTxnFee, _, err := fixture.MinFeeAndBalance(curStatus.LastRound)
	r.NoError(err)

	// use the runningAuction object to verify correct auction end.
	ra := at.Auctions[auctionID.AuctionID]
	bidOutcomes := ra.Settle(false)
	fixture.CrossVerifyEndOfAuction(params, bidOutcomes, false)
	// confirm that algos were paid to the bidder's account.
	libGoalClient := fixture.GetLibGoalClient()
	actualBalanceResp, _ := libGoalClient.AccountInformation(biddingAccount)
	algosDesired := currencySpentOnAllBids / pricePerAlgo.Price
	actualBalance := actualBalanceResp.Amount
	expectedBalance := initialBalance + algosDesired - minTxnFee*uint64(numBids) // bidder pays fees for each bid
	r.True(actualBalance > expectedBalance, "bidder started with %d algos, then tried to buy %d algos, so should have at least %d algos. instead, have %d algos", initialBalance, algosDesired, expectedBalance, actualBalance)
	r.Equal(len(bidOutcomes.Outcomes), numBids, "each bid should produce a bidOutcome")
}

func TestStartAndEndAuctionTenUsersOneBidEach(t *testing.T) {
	t.Skip("Disabling since they need work and shouldn't block releases")
	t.Parallel()
	r := require.New(fixtures.SynchronizedTest(t))
	var fixture fixtures.AuctionFixture
	netTemplate := filepath.Join("nettemplates", "TwoNodes50Each.json")
	auctionParamFile := filepath.Join("auctions", "AuctionParams_1.json")
	fixture.Setup(t, netTemplate)
	defer fixture.Shutdown()
	libGoalClient := fixture.GetLibGoalClient()

	minTxnFee, minAcctBalance, err := fixture.CurrentMinFeeAndBalance()
	r.NoError(err)

	// create wallets to bid with, and note their balances before the auction.
	wallets, _ := fixture.GetWalletsSortedByBalance()
	fundingAccount := wallets[0].Address
	minimumBalance := minAcctBalance
	fundingAmount := uint64(5) * minimumBalance
	initialBalance := fundingAmount
	txnFee := minTxnFee
	numBids := 10
	txidsToAccounts := make(map[string]string)
	var bidders []string
	walletHandle, _, err := fixture.GetDefaultWalletAndPassword()
	for i := 0; i < numBids; i++ {
		newAccount, _ := libGoalClient.GenerateAddress(walletHandle)
		tx, _ := libGoalClient.SendPaymentFromUnencryptedWallet(fundingAccount, newAccount, txnFee, fundingAmount, nil)
		txidsToAccounts[tx.ID().String()] = newAccount
		bidders = append(bidders, newAccount)
	}
	// start the auction.
	fileParams, _, _, _, err := fixture.StartAuction(auctionParamFile)
	allTxnsConfirmTimeout := fileParams.FirstRound
	if !fixture.WaitForAllTxnsToConfirm(allTxnsConfirmTimeout, txidsToAccounts) {
		r.Fail("Funding bid accounts failed. Failing out")
	}
	r.NoError(err)
	// start tracking the auction.
	at, err := fixture.GetAuctionTracker()
	r.NoError(err)
	// build bids. bidders spend all their currency at whatever current price.
	dollarsDeposited := 100
	centsDeposited := uint64(dollarsDeposited * 100)
	console := fixture.GetAuctionConsoleRestClient()
	// wait for the console to notice the auction
	auctionID, err := fixture.WaitForNonZeroAuctionID()
	r.NoError(err)
	// auction console is populated, populate empty params values
	auctionKey, err := fixture.GetAuctionMasterPublicKey()
	r.NoError(err)
	paramsResponse, err := fixture.GetAuctionConsoleRestClient().Params(auctionID.AuctionID)
	r.NoError(err)
	params := paramsResponse.Params
	fixture.WaitForRoundWithTimeout(params.FirstRound + uint64(1))
	curStatus, _ := fixture.GetAlgodRestClient().Status()
	pricePerAlgo, err := console.CurrentPrice(auctionID.AuctionID, curStatus.LastRound)
	detectAuctionCannotProceed(r, params, curStatus.LastRound, pricePerAlgo.Price)
	currencySpentOnBid := centsDeposited
	for _, bidder := range bidders {
		bidID := uint64(0)
		price := pricePerAlgo.Price
		if price == 0 {
			price, _ = fixture.ComputeCurrentPrice(curStatus.LastRound, params.FirstRound, params.NumChunks, params.PriceChunkRounds, params.LastPrice, params.MaxPriceMultiple)
			price = price + 1
		}
		txid, _, err := fixture.MakeAndPostBidAndDeposit(bidID, auctionID.AuctionID, auctionKey, bidder, price, currencySpentOnBid)
		r.NoError(err)
		fixture.AssertValidTxid(txid)
	}
	// wait for the auction to end, then call auction-end script.
	err = fixture.WaitForRoundWithTimeout(params.FirstRound + params.PriceChunkRounds*params.NumChunks)
	r.NoError(err)
	_, _, err = fixture.EndAuction()
	r.NoError(err)
	// the auction-end script posts transactions. wait a round for them to clear.
	fixture.WaitForNextRound()
	// use the runningAuction object to verify correct auction end.
	ra := at.Auctions[auctionID.AuctionID]
	bidOutcomes := ra.Settle(false)
	fixture.CrossVerifyEndOfAuction(params, bidOutcomes, false)
	r.Equal(numBids, len(bidOutcomes.Outcomes), "each bid should produce a bidOutcome")
	r.Equal(len(bidders), len(bidOutcomes.Outcomes), "each bidder should produce a single bidOutcome")
	for _, bidder := range bidders {
		// confirm that algos were paid to the bidder's account.
		actualBalanceResp, _ := libGoalClient.AccountInformation(bidder)
		algosDesired := currencySpentOnBid / pricePerAlgo.Price
		actualBalance := actualBalanceResp.Amount
		expectedBalance := initialBalance + algosDesired - txnFee // bidder pays 1 algo for each bid
		r.True(actualBalance > expectedBalance, "bidder started with %d algos, then tried to buy %d algos, so should have at least %d algos. instead, have %d algos", initialBalance, algosDesired, expectedBalance, actualBalance)
	}
}

func TestStartAndEndAuctionTenUsersTenBidsEach(t *testing.T) {
	t.Skip("Disabling since they need work and shouldn't block releases")
	if runtime.GOOS == "darwin" {
		t.Skip()
	}
	t.Parallel()
	r := require.New(fixtures.SynchronizedTest(t))
	var fixture fixtures.AuctionFixture
	netTemplate := filepath.Join("nettemplates", "TwoNodes50Each.json")
	auctionParamFile := filepath.Join("auctions", "AuctionParams_1.json")
	fixture.Setup(t, netTemplate)
	defer fixture.Shutdown()
	libGoalClient := fixture.GetLibGoalClient()

	minTxnFee, minAcctBalance, err := fixture.CurrentMinFeeAndBalance()
	r.NoError(err)

	// create wallets to bid with, and note their balances before the auction.
	wallets, _ := fixture.GetWalletsSortedByBalance()
	fundingAccount := wallets[0].Address
	txnFee := minTxnFee
	numBidsEach := 10
	numBidders := numBidsEach
	minBalance := minAcctBalance * 3 / 2
	fundingAmount := txnFee*uint64(numBidsEach) + minBalance
	initialBalance := fundingAmount
	txidsToAccounts := make(map[string]string)
	walletHandle, _, err := fixture.GetDefaultWalletAndPassword()
	var bidders []string
	for i := 0; i < numBidders; i++ {
		newAccount, _ := libGoalClient.GenerateAddress(walletHandle)
		tx, _ := libGoalClient.SendPaymentFromUnencryptedWallet(fundingAccount, newAccount, txnFee, fundingAmount, nil)
		txidsToAccounts[tx.ID().String()] = newAccount
		bidders = append(bidders, newAccount)
	}
	// start the auction.
	fileParams, _, _, _, err := fixture.StartAuction(auctionParamFile)
	allTxnsConfirmTimeout := fileParams.FirstRound
	if !fixture.WaitForAllTxnsToConfirm(allTxnsConfirmTimeout, txidsToAccounts) {
		r.Fail("Funding bid accounts failed. Failing out")
	}
	r.NoError(err)
	// start tracking the auction.
	at, err := fixture.GetAuctionTracker()
	r.NoError(err)
	// build bids. bidders spend all their currency at whatever current price.
	dollarsDeposited := 100
	centsDeposited := uint64(dollarsDeposited * 100)
	console := fixture.GetAuctionConsoleRestClient()
	// wait for the console to notice the auction
	auctionID, err := fixture.WaitForNonZeroAuctionID()
	r.NoError(err)
	// auction console is populated, populate empty params values
	auctionKey, err := fixture.GetAuctionMasterPublicKey()
	r.NoError(err)
	paramsResponse, err := fixture.GetAuctionConsoleRestClient().Params(auctionID.AuctionID)
	r.NoError(err)
	params := paramsResponse.Params
	fixture.WaitForRoundWithTimeout(params.FirstRound + uint64(1))
	curStatus, _ := fixture.GetAlgodRestClient().Status()
	pricePerAlgo, err := console.CurrentPrice(auctionID.AuctionID, curStatus.LastRound)
	detectAuctionCannotProceed(r, params, curStatus.LastRound, pricePerAlgo.Price)
	currencySpentOnEachBid := centsDeposited / uint64(numBidsEach)
	for i := 0; i < numBidsEach; i++ {
		bidID := uint64(i)
		for _, bidder := range bidders {
			price := pricePerAlgo.Price
			if price == 0 {
				price, _ = fixture.ComputeCurrentPrice(curStatus.LastRound, params.FirstRound, params.NumChunks, params.PriceChunkRounds, params.LastPrice, params.MaxPriceMultiple)
				price = price + 1
			}
			txid, _, err := fixture.MakeAndPostBidAndDeposit(bidID, auctionID.AuctionID, auctionKey, bidder, price, currencySpentOnEachBid)
			r.NoError(err)
			t.Logf("MakeAndPostBidAndDeposit() returned transaction id %s", txid)
		}
	}
	// wait for the auction to end, then call auction-end script.
	err = fixture.WaitForRoundWithTimeout(params.FirstRound + params.PriceChunkRounds*params.NumChunks)
	r.NoError(err)
	_, _, err = fixture.EndAuction()
	r.NoError(err)
	// the auction-end script posts transactions. wait a round for them to clear.
	fixture.WaitForNextRound()
	// use the runningAuction object to verify correct auction end.
	ra := at.Auctions[auctionID.AuctionID]
	bidOutcomes := ra.Settle(false)
	fixture.CrossVerifyEndOfAuction(params, bidOutcomes, false)
	r.Equal(numBidsEach*numBidders, len(bidOutcomes.Outcomes), "each of a bidder's bids should produce a bidOutcome")
	for _, bidder := range bidders {
		// confirm that algos were paid to the bidder's account.
		actualBalanceResp, _ := libGoalClient.AccountInformation(bidder)
		algosDesired := (currencySpentOnEachBid / pricePerAlgo.Price) * uint64(numBidsEach)
		actualBalance := actualBalanceResp.Amount
		expectedBalance := initialBalance + algosDesired - (txnFee * uint64(numBidsEach)) // bidder pays 1 algo for each bid
		r.True(actualBalance > expectedBalance, "bidder %v started with %d algos, then tried to buy %d algos, so should have at least %d algos. instead, have %d algos", bidder, initialBalance, algosDesired, expectedBalance, actualBalance)
	}
}

func TestDecayingPrice(t *testing.T) {
	t.Skip("Disabling since they need work and shouldn't block releases")
	if runtime.GOOS == "darwin" {
		t.Skip()
	}
	t.Parallel()
	r := require.New(fixtures.SynchronizedTest(t))
	var fixture fixtures.AuctionFixture
	netTemplate := filepath.Join("nettemplates", "TwoNodes50Each.json")
	// "price goes from 10 to 1, decreasing by 1 each block for 10 blocks."
	auctionParamFile := filepath.Join("auctions", "TenBlocksTenPriceSteps.json")
	fixture.Setup(t, netTemplate)
	defer fixture.Shutdown()
	client := fixture.GetAlgodRestClient()

	// start the auction
	_, _, _, _, err := fixture.StartAuction(auctionParamFile)
	r.NoError(err)
	// wait for the console to notice the auction
	auctionID, err := fixture.WaitForNonZeroAuctionID()
	r.NoError(err)
	paramsResponse, err := fixture.GetAuctionConsoleRestClient().Params(auctionID.AuctionID)
	r.NoError(err)
	params := paramsResponse.Params
	numRounds := params.PriceChunkRounds * params.NumChunks
	expectedInitialPrice := params.LastPrice * params.MaxPriceMultiple
	fixture.WaitForRoundWithTimeout(params.FirstRound)
	for i := 0; uint64(i) < numRounds; i++ {
		status, _ := client.Status()
		curRound := status.LastRound
		if curRound >= params.FirstRound+numRounds {
			// auction's already over, time to clean up.
			break
		}
		expectedPrice := expectedInitialPrice - (curRound - params.FirstRound)
		pricePerAlgo, err := fixture.GetAuctionConsoleRestClient().CurrentPrice(params.AuctionID, curRound)
		r.Equal(expectedPrice, pricePerAlgo.Price)
		r.True(pricePerAlgo.Success)
		r.Equal(curRound, pricePerAlgo.Round)
		r.Equal(params.AuctionID, pricePerAlgo.AuctionID)
		r.NoError(err)
		err = fixture.WaitForRoundWithTimeout(curRound + uint64(1))
		r.NoError(err)
	}
	// end the auction
	fixture.EndAuction()
}
