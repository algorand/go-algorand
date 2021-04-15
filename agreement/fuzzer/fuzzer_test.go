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

package fuzzer

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/agreement/gossip"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/timers"
)

// Fuzzer is a container for the entire network stack across all the nodes.
type Fuzzer struct {
	nodesCount       int
	networkName      string
	wallClock        int32
	agreements       []*agreement.Service
	facades          []*NetworkFacade
	clocks           []timers.Clock
	disconnected     [][]bool
	crashAccessors   []db.Accessor
	router           *Router
	log              logging.Logger
	accounts         []account.Participation
	balances         map[basics.Address]basics.AccountData
	accountAccessors []db.Accessor
	ledgers          []*testLedger
	tickGranularity  time.Duration
	disconnectMu     deadlock.Mutex
	accelerateClock  bool
	blockValidator   agreement.BlockValidator
	agreementParams  []agreement.Parameters
	disableTraces    bool
}

type FuzzerConfig struct {
	FuzzerName    string
	NodesCount    int
	OnlineNodes   []bool
	Filters       []NetworkFilterFactory
	LogLevel      logging.Level
	DisableTraces bool
}

// MakeFuzzer creates a fuzzer object with nodesCount nodes.
func MakeFuzzer(config FuzzerConfig) *Fuzzer {
	n := &Fuzzer{
		nodesCount:       config.NodesCount,
		networkName:      config.FuzzerName,
		agreements:       make([]*agreement.Service, config.NodesCount),
		facades:          make([]*NetworkFacade, config.NodesCount),
		clocks:           make([]timers.Clock, config.NodesCount),
		disconnected:     make([][]bool, config.NodesCount),
		crashAccessors:   make([]db.Accessor, config.NodesCount),
		accounts:         make([]account.Participation, config.NodesCount),
		balances:         make(map[basics.Address]basics.AccountData),
		accountAccessors: make([]db.Accessor, config.NodesCount*2),
		ledgers:          make([]*testLedger, config.NodesCount),
		agreementParams:  make([]agreement.Parameters, config.NodesCount),
		tickGranularity:  time.Millisecond * 300,
		accelerateClock:  true,
		blockValidator:   testBlockValidator{},
		disableTraces:    config.DisableTraces,
	}

	n.router = MakeRouter(n)

	// logging
	n.log = logging.Base()
	f, err := os.Create(n.networkName + ".log")
	if err != nil {
		return nil
	}
	n.log.SetJSONFormatter()
	n.log.SetOutput(f)
	n.log.SetLevel(config.LogLevel)

	n.initAccountsAndBalances((&[32]byte{})[:], config.OnlineNodes)
	for i := range n.agreements {
		if !n.initAgreementNode(i, config.Filters...) {
			return nil
		}
	}
	return n
}

func (n *Fuzzer) initAgreementNode(nodeID int, filters ...NetworkFilterFactory) bool {
	var err error

	n.disconnected[nodeID] = make([]bool, n.nodesCount)
	n.facades[nodeID] = MakeNetworkFacade(n, nodeID)
	n.ledgers[nodeID] = makeTestLedger(n.balances, n.LedgerSync)
	n.clocks[nodeID] = n.facades[nodeID]

	n.crashAccessors[nodeID], err = db.MakeAccessor(n.networkName+"_"+strconv.Itoa(nodeID)+"_crash.db", false, true)
	if err != nil {
		return false
	}

	logger := n.log.WithFields(logging.Fields{"Source": "service-" + strconv.Itoa(nodeID)})
	n.agreementParams[nodeID] = agreement.Parameters{
		Logger:                  logger,
		Ledger:                  n.ledgers[nodeID],
		Network:                 gossip.WrapNetwork(n.facades[nodeID], logger),
		KeyManager:              simpleKeyManager(n.accounts[nodeID : nodeID+1]),
		BlockValidator:          n.blockValidator,
		BlockFactory:            testBlockFactory{Owner: nodeID},
		Clock:                   n.clocks[nodeID],
		Accessor:                n.crashAccessors[nodeID],
		Local:                   config.Local{CadaverSizeTarget: 10000000},
		RandomSource:            n.facades[nodeID],
		EventsProcessingMonitor: n.facades[nodeID],
	}

	cadaverFilename := fmt.Sprintf("%v-%v", n.networkName, nodeID)
	os.Remove(cadaverFilename + ".cdv")
	os.Remove(cadaverFilename + ".cdv.archive")
	if n.disableTraces == true {
		cadaverFilename = ""
	}

	n.agreements[nodeID] = agreement.MakeService(n.agreementParams[nodeID])

	n.agreements[nodeID].SetTracerFilename(cadaverFilename)

	n.initFiltersChain(nodeID, filters...)

	return true
}

func (n *Fuzzer) initFiltersChain(nodeID int, filters ...NetworkFilterFactory) {
	currentFilter := NetworkFilter(n.facades[nodeID])
	// create concrete filters.
	c := make([]NetworkFilter, len(filters))
	for i, filter := range filters {
		c[i] = filter.CreateFilter(nodeID, n)
	}
	for _, filter := range c {
		currentFilter.SetDownstreamFilter(filter)
		filter.SetUpstreamFilter(currentFilter)
		currentFilter = filter
	}

	// set the last one with the router.
	currentFilter.SetDownstreamFilter(n.router)
}

func (n *Fuzzer) initAccountsAndBalances(rootSeed []byte, onlineNodes []bool) error {
	off := int(rand.Uint32() >> 2) // prevent name collision from running tests more than once

	// system state setup: keygen, stake initialization
	var seed crypto.Seed
	copy(seed[:], rootSeed)

	if n.nodesCount > len(readOnlyParticipationVotes) {
		panic("Too many accounts.")
	}

	for i := 0; i < n.nodesCount; i++ {
		stake := basics.MicroAlgos{Raw: 1000000}
		firstValid := basics.Round(0)
		lastValid := basics.Round(1000)

		rootAccess, err := db.MakeAccessor(n.networkName+"root"+strconv.Itoa(i+off), false, true)

		if err != nil {
			return err
		}
		n.accountAccessors[i*2+0] = rootAccess

		seed = sha256.Sum256(seed[:])
		root, err := account.ImportRoot(rootAccess, seed)
		if err != nil {
			panic(err)
		}
		rootAddress := root.Address()

		n.accounts[i] = account.Participation{
			Parent:     rootAddress,
			VRF:        generatePseudoRandomVRF(i),
			Voting:     readOnlyParticipationVotes[i],
			FirstValid: firstValid,
			LastValid:  lastValid,
		}

		acctData := basics.AccountData{
			Status:      basics.Online,
			MicroAlgos:  stake,
			VoteID:      n.accounts[i].VotingSecrets().OneTimeSignatureVerifier,
			SelectionID: n.accounts[i].VRFSecrets().PK,
		}
		if len(onlineNodes) > i {
			if onlineNodes[i] == false {
				acctData.Status = basics.Offline
			}
		}
		n.balances[rootAddress] = acctData
	}
	return nil
}

// Disconnect would disconnect node diconnectingNode from node disconnectedNode ensuring that no futher messages
// from disconnectedNode would reach diconnectingNode
func (n *Fuzzer) Disconnect(diconnectingNode, disconnectedNode int) {
	n.disconnectMu.Lock()
	defer n.disconnectMu.Unlock()
	// by default, the disconnect is symmetric.
	n.disconnected[diconnectingNode][disconnectedNode] = true
	n.disconnected[disconnectedNode][diconnectingNode] = true
}

func (n *Fuzzer) IsDisconnected(diconnectingNode, disconnectedNode int) bool {
	n.disconnectMu.Lock()
	defer n.disconnectMu.Unlock()
	return n.disconnected[disconnectedNode][diconnectingNode]
}

func (n *Fuzzer) Start() {
	n.router.Start()
	for i, s := range n.agreements {
		s.Start()
		n.facades[i].WaitForTimeoutAt()
	}
	for _, f := range n.facades {
		// wait until no activity.
		f.WaitForEventsQueue(true)
	}
}

func (n *Fuzzer) InvokeFiltersShutdown(preshutdown bool) {
	for _, facade := range n.facades {
		dsFilter := facade.GetDownstreamFilter()
		for {
			nextDsFilter := dsFilter.GetDownstreamFilter()
			if nextDsFilter == nil {
				break
			}
			if shutdown, has := dsFilter.(ShutdownFilter); has {
				if preshutdown {
					shutdown.PreShutdown()
				} else {
					shutdown.PostShutdown()
				}
			}
			dsFilter = nextDsFilter
		}
	}
}

func (n *Fuzzer) Shutdown() {
	for {
		if activity, _ := n.exhaustNetworkOperations(); !activity {
			break
		}
	}
	n.InvokeFiltersShutdown(true)

	for _, s := range n.agreements {

		s.Shutdown()
	}
	n.router.Shutdown()
	n.InvokeFiltersShutdown(false)
	for _, c := range n.crashAccessors {
		c.Close()
	}
	for _, c := range n.accountAccessors {
		c.Close()
	}
}

func (n *Fuzzer) WallClock() int {
	return int(atomic.LoadInt32(&n.wallClock))
}

func (n *Fuzzer) RemoveFilters() {
	for _, f := range n.facades {
		f.SetDownstreamFilter(n.router)
		f.Rezero()
	}
	n.disconnectMu.Lock()
	defer n.disconnectMu.Unlock()
	for i := range n.disconnected {
		n.disconnected[i] = make([]bool, n.nodesCount)
	}
}

func (n *Fuzzer) CheckRounds() (lowRound, highRound basics.Round) {
	lowRound = n.ledgers[0].NextRound()
	highRound = n.ledgers[0].NextRound()
	// check the round.
	for _, l := range n.ledgers {
		if l.NextRound() < lowRound {
			lowRound = l.NextRound()
		}
		if l.NextRound() > highRound {
			highRound = l.NextRound()
		}
	}
	return
}

func (n *Fuzzer) LedgerSync(l *testLedger, r basics.Round, c agreement.Certificate) bool {
	var o *testLedger
	// find a ledger that has the round r
	for _, l := range n.ledgers {
		if l.NextRound() > r {
			o = l
			break
		}
	}
	if o == nil {
		return false
	}
	l.Catchup(o, r+1)
	return true
}

// set the catchup flag for the node so that we can continuesly catch up the node.
// once the node is keeping up, this would get disabled.
func (n *Fuzzer) StartCatchingUp(nodeID int) {
	if nodeID == -1 {
		for nodeID := range n.ledgers {
			n.ledgers[nodeID].catchingUp = true
		}
	} else {
		n.ledgers[nodeID].catchingUp = true
	}
}

func (n *Fuzzer) Catchup(nodeID int) {
	// find the ledger with the highest round.
	highRoundLedger := n.ledgers[0]
	highRound := highRoundLedger.NextRound()
	for _, l := range n.ledgers {
		if l.NextRound() > highRound {
			highRoundLedger = l
			highRound = highRoundLedger.NextRound()

		}
	}

	if nodeID == -1 {
		// catchup all the reminder ones.
		for i, l := range n.ledgers {
			if l.NextRound() < highRound {
				l.Catchup(highRoundLedger, highRound)
				n.facades[i].WaitForEventsQueue(false) // wait for non zero
				n.facades[i].WaitForEventsQueue(true)  // wait for zero
			}
		}
	} else {
		if n.ledgers[nodeID].NextRound() < highRound {
			n.ledgers[nodeID].Catchup(highRoundLedger, highRound)
			n.facades[nodeID].WaitForEventsQueue(false) // wait for non zero
			n.facades[nodeID].WaitForEventsQueue(true)  // wait for zero
		}
	}
}

type RunResult struct {
	StartLowRound, StartHighRound               basics.Round
	PreRecoveryLowRound, PreRecoveryHighRound   basics.Round
	PostRecoveryLowRound, PostRecoveryHighRound basics.Round
	NetworkStalled                              bool
}

func (n *Fuzzer) pushDownstreamMessage(newMsg context.CancelFunc) bool {
	for _, facade := range n.facades {
		hasMessage := false
		for facade.PushDownstreamMessage(newMsg) {
			hasMessage = true
		}
		if hasMessage {
			return true
		}
	}
	return false
}

func (n *Fuzzer) pushUpstreamMessage() (messageSent bool) {
	for targetNode := 0; targetNode < n.nodesCount; targetNode++ {
		for n.router.hasPendingMessage(targetNode, "") {
			n.router.sendMessage(targetNode, "")
			messageSent = true
		}
	}
	return
}

func (n *Fuzzer) CheckBlockingEnsureDigest() {
	// do we have any blocking ensure digest ?
	hasBlocking := false
	for _, l := range n.ledgers {
		if l.IsEnsuringDigest() {
			hasBlocking = true
			break
		}
	}
	if hasBlocking == false {
		return
	}
	_, highRound := n.CheckRounds()

	for _, l := range n.ledgers {
		if !l.IsEnsuringDigest() {
			continue
		}
		if l.NextRound() < highRound {
			l.TryEnsuringDigest()
			// wait until done.
			<-l.GetEnsuringDigestCh(false)
		}
	}
}

func (n *Fuzzer) exhaustNetworkOperations() (networkActivity bool, ticks int) {
	networkOps := true
	networkActivity = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for networkOps {
		networkOps = false
		if n.pushDownstreamMessage(cancel) {
			networkOps = true
			networkActivity = true
		}
		if networkActivity := n.pushUpstreamMessage(); networkActivity {
			networkOps = true
		}
		if networkOps {
			cancel()
			continue
		}

		// networkOps is false here.
		select {
		case <-ctx.Done():
			networkActivity = true
			networkOps = true
			ctx, cancel = context.WithCancel(context.Background())
			defer cancel()
		default:
			cancel()
			ticks++
			return
		}
	}
	return
}

func (n *Fuzzer) checkCatchup() {
	for nodeID, ledger := range n.ledgers {
		if ledger.catchingUp {
			n.Catchup(nodeID)
		}
	}
}

func (n *Fuzzer) runLoop(ticksCount, inactivityThreshold int, runResult *RunResult) bool {
	clockAccelaration := int32(1)
	networkInactivityCounter := 0
	for tick := 0; tick < ticksCount; tick++ {

		networkActivity, extraTicks := n.exhaustNetworkOperations()
		tick += extraTicks

		if networkActivity {
			clockAccelaration = 1
			networkInactivityCounter = 0
		} else {
			// no activity, increase clock speed.
			if n.accelerateClock {
				clockAccelaration += clockAccelaration
			}
			networkInactivityCounter++
		}
		networkActivity = n.router.Tick(int(atomic.AddInt32(&n.wallClock, clockAccelaration)))
		if networkInactivityCounter > inactivityThreshold {
			runResult.NetworkStalled = true
			return false
		}
		if networkActivity {
			clockAccelaration = 1
		}
		n.CheckBlockingEnsureDigest()

		n.checkCatchup()
	}
	return true
}

func (n *Fuzzer) Run(trialTicks, recoveryTicks, inactivityTicks int) (bool, *RunResult) {
	var runResult RunResult
	runResult.StartLowRound, runResult.StartHighRound = n.CheckRounds()

	// perform trial test :
	if !n.runLoop(trialTicks, inactivityTicks, &runResult) {
		return false, &runResult
	}

	// check the round.
	runResult.PreRecoveryLowRound, runResult.PreRecoveryHighRound = n.CheckRounds()

	if recoveryTicks == 0 {
		return true, &runResult
	}

	n.StartCatchingUp(-1)
	n.RemoveFilters()

	// perform the recovery phase
	if !n.runLoop(recoveryTicks, inactivityTicks, &runResult) {
		return false, &runResult
	}

	// wait for the network to be inactive.
	networkInactivityCounter := 0
	for {
		networkActivity, _ := n.exhaustNetworkOperations()
		if !networkActivity {
			break
		}
		networkInactivityCounter++
		if networkInactivityCounter > inactivityTicks {
			runResult.NetworkStalled = true
			return false, &runResult
		}
	}

	// check the round.
	runResult.PostRecoveryLowRound, runResult.PostRecoveryHighRound = n.CheckRounds()
	return runResult.PostRecoveryLowRound == runResult.PostRecoveryHighRound, &runResult
}

func (n *Fuzzer) CrashNode(nodeID int) {
	if nodeID < 0 {
		return
	}
	if n.ledgers[nodeID].IsEnsuringDigest() {
		panic("Cannot crash a node while ledger is trying to ensure digest")
	}

	// we need to clear the timeouts, since we want to wait for the timeouts from the new agreement service.
	n.facades[nodeID].Zero()
	n.facades[nodeID].ClearHandlers()
	n.ledgers[nodeID].ClearNotifications()

	n.agreementParams[nodeID].Network = gossip.WrapNetwork(n.facades[nodeID], n.log)
	n.agreements[nodeID] = agreement.MakeService(n.agreementParams[nodeID])

	cadaverFilename := fmt.Sprintf("%v-%v", n.networkName, nodeID)
	if n.disableTraces == true {
		cadaverFilename = ""
	}

	n.agreements[nodeID].SetTracerFilename(cadaverFilename)
	n.facades[nodeID].ResetWaitForTimeoutAt()
	n.agreements[nodeID].Start()
	n.facades[nodeID].WaitForTimeoutAt()
	n.facades[nodeID].WaitForEventsQueue(true)
}
