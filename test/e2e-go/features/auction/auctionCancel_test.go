package auction

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func TestStartAndCancelAuctionNoBids(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	var fixture fixtures.AuctionFixture
	netTemplate := filepath.Join("nettemplates", "ThreeNodesEvenDist.json")
	auctionParamFile := filepath.Join("auctions", "AuctionParams_1.json")
	fixture.Setup(t, netTemplate)
	defer fixture.Shutdown()

	// start the auction
	_, params, _, _, err := fixture.StartAuction(auctionParamFile)
	r.NoError(err)
	// confirm the auctiontracker isn't errored
	_, err = fixture.GetAuctionTracker()
	r.NoError(err)
	// wait for the last round of the auction to pass by
	// wait for ALL nodes to confirm last round has passed by
	lastRound := params.FirstRound + params.PriceChunkRounds*params.NumChunks
	r.NoError(fixture.WaitForRoundWithTimeout(lastRound + uint64(1)))
	otherClient1 := fixture.GetLibGoalClientForNamedNode("Node1")
	r.NoError(fixture.LibGoalFixture.ClientWaitForRoundWithTimeout(otherClient1, lastRound+uint64(1)))
	otherClient2 := fixture.GetLibGoalClientForNamedNode("Node2")
	r.NoError(fixture.LibGoalFixture.ClientWaitForRoundWithTimeout(otherClient2, lastRound+uint64(1)))
	// cancel the auction, rather than settling up
	_, _, err = fixture.CancelAuction()
	r.NoError(err)
}

func TestStartAndCancelAuctionOneUserTenBids(t *testing.T) {
	t.Parallel()
	r := require.New(t)
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
	// wait for the auction to end, then call auction-cancel script.
	fixture.WaitForRoundWithTimeout(params.FirstRound + params.PriceChunkRounds*params.NumChunks)
	_, _, err = fixture.CancelAuction()
	r.NoError(err)
	// the auction-end script posts transactions. wait a round for them to clear.
	fixture.WaitForNextRound()

	// use the runningAuction object to verify correct auction end.
	ra := at.Auctions[auctionID.AuctionID]
	cancelled := true
	bidOutcomes := ra.Settle(cancelled)
	fixture.CrossVerifyEndOfAuction(params, bidOutcomes, cancelled)
	r.NoError(err)
	r.Equal(len(bidOutcomes.Outcomes), 0, "no outcomes should come from a cancelled auction")
}

func TestStartAndCancelAuctionEarlyOneUserTenBids(t *testing.T) {
	t.Parallel()
	r := require.New(t)
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
	// don't wait for the auction to end, just immediately call auction-cancel script.
	_, _, err = fixture.CancelAuction()
	r.NoError(err)
	// the auction-end script posts transactions. wait a round for them to clear.
	fixture.WaitForNextRound()

	// use the runningAuction object to verify correct auction end.
	ra := at.Auctions[auctionID.AuctionID]
	cancelled := true
	bidOutcomes := ra.Settle(cancelled)
	fixture.CrossVerifyEndOfAuction(params, bidOutcomes, cancelled)
	r.NoError(err)
	r.Equal(len(bidOutcomes.Outcomes), 0, "no outcomes should come from a cancelled auction")
}
