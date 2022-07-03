package stateproofs

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

type accountFetcher struct {
	nodeName      string
	accountNumber int
}

func (a accountFetcher) getAccount(r *require.Assertions, f *fixtures.RestClientFixture) string {
	node0Client := f.GetLibGoalClientForNamedNode(a.nodeName)
	node0Wallet, err := node0Client.GetUnencryptedWalletHandle()
	r.NoError(err)
	node0AccountList, err := node0Client.ListAddresses(node0Wallet)
	r.NoError(err)
	return node0AccountList[a.accountNumber]
}

func (a accountFetcher) getBalance(r *require.Assertions, f *fixtures.RestClientFixture) uint64 {
	account := a.getAccount(r, f)
	balance, _ := f.GetBalanceAndRound(account)
	return balance
}

type paymentSender struct {
	from   accountFetcher
	to     accountFetcher
	amount uint64
}

func (p paymentSender) sendPayment(a *require.Assertions, f *fixtures.RestClientFixture, round uint64) {
	account0 := p.from.getAccount(a, f)
	account1 := p.to.getAccount(a, f)

	minTxnFee, _, err := f.CurrentMinFeeAndBalance()
	a.NoError(err)

	client0 := f.GetLibGoalClientForNamedNode(p.from.nodeName)
	_, err = client0.SendPaymentFromUnencryptedWallet(account0, account1, minTxnFee, p.amount, []byte{byte(round)})
	a.NoError(err)
}

func TestAttestorsChangeTest(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	assert := require.New(fixtures.SynchronizedTest(t))

	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("test-fast-stateproofs")
	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	consensusParams.StateProofInterval = 16
	consensusParams.StateProofTopVoters = 1024
	consensusParams.StateProofVotersLookback = 2
	consensusParams.StateProofWeightThreshold = (1 << 32) * 51 / 100
	consensusParams.StateProofStrengthTarget = 256
	consensusParams.StateProofRecoveryInterval = 6
	consensusParams.EnableStateProofKeyregCheck = true
	consensusParams.AgreementFilterTimeout = 1500 * time.Millisecond
	consensusParams.AgreementFilterTimeoutPeriod0 = 1500 * time.Millisecond
	configurableConsensus[consensusVersion] = consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "RichAccountStateProof.json"))
	defer fixture.Shutdown()

	restClient, err := fixture.NC.AlgodClient()
	assert.NoError(err)

	var lastStateProofBlock bookkeeping.Block
	var lastStateProofMessage stateproofmsg.Message
	libgoal := fixture.LibGoalClient

	expectedNumberOfStateProofs := uint64(4)
	// Loop through the rounds enough to check for expectedNumberOfStateProofs state proofs

	paymentMaker := paymentSender{
		from: accountFetcher{nodeName: "richNode", accountNumber: 0},
		to:   accountFetcher{nodeName: "poorNode", accountNumber: 0},
	}

	for rnd := uint64(1); rnd <= consensusParams.StateProofInterval*(expectedNumberOfStateProofs+1); rnd++ {
		paymentMaker.amount = 1 // When we set the amount value to 1, it's a dummy payment, so we do not have an empty block.

		// Changing the amount to pay. This should transfer most of the money from the rich node to the poort node.
		if consensusParams.StateProofInterval*2 == rnd {
			balance := paymentMaker.from.getBalance(assert, &fixture)
			paymentMaker.amount = uint64(float64(balance*3) / 4) // taking 3/4 of the balance.
		}

		// ensuring that before the test, the rich node (from) has a significantly larger balance.
		if consensusParams.StateProofInterval*2 == rnd {
			assert.True(paymentMaker.from.getBalance(assert, &fixture)/2 > paymentMaker.to.getBalance(assert, &fixture))
		}

		// verifies that rich account transferred most of its money to the account that sits on poorNode.
		if consensusParams.StateProofInterval*3 == rnd {
			assert.True(paymentMaker.to.getBalance(assert, &fixture) > paymentMaker.from.getBalance(assert, &fixture))
		}

		paymentMaker.sendPayment(assert, &fixture, rnd)

		assert.NoError(fixture.WaitForRound(rnd, 30*time.Second))

		blk, err := libgoal.BookkeepingBlock(rnd)
		assert.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		if (rnd % consensusParams.StateProofInterval) == 0 {
			// Must have a merkle commitment for participants
			assert.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) > 0)
			assert.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight != basics.MicroAlgos{})

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastStateProofBlock.Round() == 0 {
				lastStateProofBlock = blk
			}
		} else {
			assert.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) == 0)
			assert.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight == basics.MicroAlgos{})
		}

		for lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound &&
			lastStateProofBlock.Round() != 0 {
			nextStateProofRound := uint64(lastStateProofBlock.Round()) + consensusParams.StateProofInterval

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(assert, libgoal, restClient, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams, expectedNumberOfStateProofs)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}

	assert.Equalf(int(consensusParams.StateProofInterval*expectedNumberOfStateProofs), int(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
}
