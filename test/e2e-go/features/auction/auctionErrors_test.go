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
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func TestInvalidDeposit(t *testing.T) {
	t.Skip("Disabling since they need work and shouldn't block releases")
	if testing.Short() {
		t.Skip()
	}
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

	// start the auction.
	_, _, _, _, err := fixture.StartAuction(auctionParamFile)
	r.NoError(err)
	// start tracking the auction.
	at, err := fixture.GetAuctionTracker()
	r.NoError(err)

	// get a wallet to bid with
	wallets, _ := fixture.GetWalletsSortedByBalance()
	biddingAccount := wallets[0].Address

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
	auctionKey, err := fixture.GetAuctionMasterPublicKey()
	r.NoError(err)
	curStatus, _ := fixture.GetAlgodRestClient().Status()
	pricePerAlgo, err := console.CurrentPrice(auctionID.AuctionID, curStatus.LastRound)
	currencySpentOnBid := centsDeposited
	// have set up bid and deposit as normal - corrupt the deposit blob, though.

	err = fixture.MakeBankAccountIfNoneExists(biddingAccount)

	r.NoError(err)

	depositBlob, err := fixture.MakeSignedDeposit(biddingAccount, auctionKey, biddingAccount, auctionID.AuctionID, currencySpentOnBid)

	r.NoError(err)

	//corrupt the deposit: zero-out the first byte of the signature (or if it is zero make it 0x01)
	if depositBlob[0] != 0 {
		depositBlob[0] = 0
	} else {
		depositBlob[0] = 1
	}

	bidBlob, err := fixture.MakeSignedBid(bidID, auctionKey, auctionID.AuctionID, biddingAccount, pricePerAlgo.Price, currencySpentOnBid)
	r.NoError(err)

	unitedBlob := append(depositBlob, bidBlob...)

	amountToPay := uint64(0)

	minTxnFee, _, err := fixture.CurrentMinFeeAndBalance()
	r.NoError(err)

	transactionFee := minTxnFee

	libGoalClient := fixture.GetLibGoalClient()

	trx, err := libGoalClient.SendPaymentFromUnencryptedWallet(biddingAccount, auctionKey, transactionFee, amountToPay, unitedBlob)
	r.NoError(err)
	fixture.AssertValidTxid(trx.ID().String())

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
	r.Len(bidOutcomes.Outcomes, 0, "corrupt deposit should produce no bid outcome")
}

func TestNoDepositAssociatedWithBid(t *testing.T) {
	t.Skip("Disabling since they need work and shouldn't block releases")
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

	// get a wallet to bid with
	wallets, _ := fixture.GetWalletsSortedByBalance()
	biddingAccount := wallets[0].Address

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
	auctionKey, err := fixture.GetAuctionMasterPublicKey()
	r.NoError(err)
	curStatus, _ := fixture.GetAlgodRestClient().Status()
	pricePerAlgo, err := console.CurrentPrice(auctionID.AuctionID, curStatus.LastRound)
	currencySpentOnBid := centsDeposited
	// have set up bid and deposit as normal - corrupt the deposit blob, though.

	bidBlob, err := fixture.MakeSignedBid(bidID, auctionKey, auctionID.AuctionID, biddingAccount, pricePerAlgo.Price, currencySpentOnBid)

	r.NoError(err)

	amountToPay := uint64(0)

	minTxnFee, _, err := fixture.CurrentMinFeeAndBalance()
	r.NoError(err)
	transactionFee := minTxnFee

	libGoalClient := fixture.GetLibGoalClient()

	tx, err := libGoalClient.SendPaymentFromUnencryptedWallet(biddingAccount, auctionKey, transactionFee, amountToPay, bidBlob) // note: no deposit blob!
	r.NoError(err)
	fixture.AssertValidTxid(tx.ID().String())

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
	r.Len(bidOutcomes.Outcomes, 0, "nil deposit should invalidate bid")
}

func TestDeadbeatBid(t *testing.T) {
	t.Skip("Disabling since they need work and shouldn't block releases")
	// an error is expected when an account attempts to overbid
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

	// get a wallet to bid with
	wallets, _ := fixture.GetWalletsSortedByBalance()
	biddingAccount := wallets[0].Address

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
	auctionKey, err := fixture.GetAuctionMasterPublicKey()
	r.NoError(err)
	curStatus, _ := fixture.GetAlgodRestClient().Status()
	pricePerAlgo, err := console.CurrentPrice(auctionID.AuctionID, curStatus.LastRound)
	currencySpentOnBid := centsDeposited * 10 // note that bidder is bidding 10x money in "bank"
	// have set up bid and deposit as normal - corrupt the deposit blob, though.

	err = fixture.MakeBankAccountIfNoneExists(biddingAccount)
	r.NoError(err)

	depositBlob, err := fixture.MakeSignedDeposit(biddingAccount, auctionKey, biddingAccount, auctionID.AuctionID, centsDeposited)
	r.NoError(err)

	bidBlob, err := fixture.MakeSignedBid(bidID, auctionKey, auctionID.AuctionID, biddingAccount, pricePerAlgo.Price, currencySpentOnBid)
	r.NoError(err)

	unitedBlob := append(depositBlob, bidBlob...)

	amountToPay := uint64(0)

	minTxnFee, _, err := fixture.CurrentMinFeeAndBalance()
	r.NoError(err)
	transactionFee := minTxnFee

	libGoalClient := fixture.GetLibGoalClient()

	tx, err := libGoalClient.SendPaymentFromUnencryptedWallet(biddingAccount, auctionKey, transactionFee, amountToPay, unitedBlob)
	// note that only the note is corrupted, so the transaction should post as normal.
	r.NoError(err)
	fixture.AssertValidTxid(tx.ID().String())

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
	r.Len(bidOutcomes.Outcomes, 0, "deadbeat bid should produce no outcome")
}

func partitionNetwork(fixture *fixtures.AuctionFixture, r *require.Assertions) {
	nc, err := fixture.GetNodeController("Node")
	r.NoError(err)
	r.NoError(nc.FullStop())
	// Give network a chance to stall
	const inducePartitionTime = 6 * time.Second // Try to minimize change of proceeding too many steps while stalled
	time.Sleep(inducePartitionTime)
}

func unpartitionNetwork(fixture *fixtures.AuctionFixture, r *require.Assertions) {
	nc, err := fixture.GetNodeController("Node")
	r.NoError(err)
	_, err = fixture.StartNode(nc.GetDataDir())
	r.NoError(err)
}

func TestStartAndPartitionAuctionTenUsersTenBidsEach(t *testing.T) {
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
		// partition the network halfway through this process
		if i == numBidsEach/2 {
			partitionNetwork(&fixture, r)
		}
	}
	unpartitionNetwork(&fixture, r)
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
