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

package agreement

//go:generate dbgen -i agree.sql -p agreement -n agree -o agreeInstall.go -h ../scripts/LICENSE_HEADER
import (
	"context"
	"fmt"
	"os"
	"reflect"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/timers"
)

const (
	defaultCadaverName = "agreement"
)

// enablePipelining returns true if env var PIPELINE is set for testing (XXX remove) or the consensus parameter is set.
// XXX mainLoop only checks this at startup time
func enablePipelining(cv protocol.ConsensusVersion) bool {
	return os.Getenv("PIPELINE") != "" || config.Consensus[cv].AgreementPipelining
}

// Service represents an instance of an execution of Algorand's agreement protocol.
type Service struct {
	parameters

	// for exiting
	quit   chan struct{}
	done   chan struct{}
	quitFn context.CancelFunc // TODO instead of storing this, pass a context into Start()

	// external events
	demux    *demux
	loopback pseudonode

	log    serviceLogger
	tracer *tracer

	voteVerifier    *AsyncVoteVerifier
	persistenceLoop *asyncPersistenceLoop

	monitor *coserviceMonitor

	persistRouter  rootRouter
	persistStatus  serializableActor
	persistActions []action

	clockManager *clockManager
}

// Parameters holds the parameters necessary to run the agreement protocol.
type Parameters struct {
	Ledger
	Network
	KeyManager
	BlockValidator
	BlockFactory
	RandomSource
	EventsProcessingMonitor
	timers.ClockFactory
	db.Accessor
	logging.Logger
	config.Local
	execpool.BacklogPool
}

// parameters is a convenience typedef for Parameters.
type parameters Parameters

// externalDemuxSignals used to syncronize the external signals that goes to the demux with the main loop.
type externalDemuxSignals struct {
	Deadline             time.Duration
	FastRecoveryDeadline time.Duration
	PipelineDelay        time.Duration
	CurrentRound         round
}

type pipelineExternalDemuxSignals struct {
	currentRound basics.Round
	signals      []externalDemuxSignals
}

// MakeService creates a new Agreement Service instance given a set of Parameters.
//
// Call Start to start execution and Shutdown to finish execution.
func MakeService(p Parameters) *Service {
	s := new(Service)

	s.parameters = parameters(p)
	s.clockManager = makeClockManager(s.ClockFactory)

	s.log = serviceLogger{Logger: p.Logger}

	// GOAL2-541: tracer is not concurrency safe. It should only ever be
	// accessed by main state machine loop.
	s.tracer = makeTracer(s.log, defaultCadaverName, p.CadaverSizeTarget,
		s.Local.EnableAgreementReporting, s.Local.EnableAgreementTimeMetrics)

	s.persistenceLoop = makeAsyncPersistenceLoop(s.log, s.Accessor, s.Ledger)

	return s
}

// SetTracerFilename updates the tracer filename used.
func (s *Service) SetTracerFilename(filename string) {
	s.tracer.cadaver.baseFilename = filename
}

// Start executing the agreement protocol.
func (s *Service) Start() {
	s.parameters.Network.Start()
	ctx, quitFn := context.WithCancel(context.Background())
	s.quitFn = quitFn

	s.quit = make(chan struct{})
	s.done = make(chan struct{})

	s.voteVerifier = MakeAsyncVoteVerifier(s.BacklogPool)
	s.demux = makeDemux(demuxParams{
		net:               s.Network,
		ledger:            s.Ledger,
		validator:         s.BlockValidator,
		voteVerifier:      s.voteVerifier,
		processingMonitor: s.EventsProcessingMonitor,
		log:               s.log,
		monitor:           s.monitor,
	})
	s.loopback = makePseudonode(pseudonodeParams{
		factory:      s.BlockFactory,
		validator:    s.BlockValidator,
		keys:         s.KeyManager,
		ledger:       s.Ledger,
		voteVerifier: s.voteVerifier,
		log:          s.log,
		monitor:      s.monitor,
	})

	s.persistenceLoop.Start()
	input := make(chan externalEvent)
	output := make(chan []action)
	ready := make(chan pipelineExternalDemuxSignals)
	go s.demuxLoop(ctx, input, output, ready)
	go s.mainLoop(input, output, ready)
}

// Shutdown the execution of the protocol.
//
// This method returns after all resources have been cleaned up.
func (s *Service) Shutdown() {
	close(s.quit)
	s.quitFn()
	<-s.done
	s.persistenceLoop.Quit()
}

// demuxLoop repeatedly executes pending actions and then requests the next event from the Service.demux.
func (s *Service) demuxLoop(ctx context.Context, input chan<- externalEvent, output <-chan []action, ready <-chan pipelineExternalDemuxSignals) {
	for a := range output {
		s.do(ctx, a)
		extSignals := <-ready
		e, ok := s.demux.next(s, extSignals)
		if !ok {
			close(input)
			break
		}
		input <- e
	}
	s.demux.quit()
	s.loopback.Quit()
	s.voteVerifier.Quit()
	close(s.done)
}

// mainLoop drives the state machine.
//
// After possibly restoring from disk and then initializing, it does the following in a loop:
// 1. Execute all pending actions.
// 2. Obtain an input event from the demultiplexer.
// 3. Drive the state machine with this input to obtain a slice of pending actions.
// 4. If necessary, persist state to disk.
func (s *Service) mainLoop(input <-chan externalEvent, output chan<- []action, ready chan<- pipelineExternalDemuxSignals) {
	// setup
	var clockManager *clockManager
	var router, router2 rootRouter
	var status, status2 serializableActor
	var a, a2 []action
	var err error
	raw, err := restore(s.log, s.Accessor)
	if err == nil {
		clockManager, router, status, a, err = decode(raw, s.clockManager)
		if err != nil {
			reset(s.log, s.Accessor)
		} else {
			s.log.Infof("decode (agreement): restored crash state from database (pending %v @ %+v)", a, status)
		}
	}
	if err != nil {
		// in this case, we don't have valid state
		// pretend a new round has just started, and propose a block
		var nextRound round
		var nextVersion protocol.ConsensusVersion
		for {
			nextRound.Number = s.Ledger.NextRound()
			if nextRound.Number == 0 {
				nextRound.Branch = bookkeeping.BlockHash{}
			} else {
				d, err := s.Ledger.LookupDigest(nextRound.Number-1, bookkeeping.BlockHash{})
				if err != nil {
					s.log.Errorf("unable to retrieve last block hash for round %d: %v", nextRound.Number-1, err)
					time.Sleep(time.Second)
					continue
				}
				nextRound.Branch = bookkeeping.BlockHash(d)
			}

			nextVersion, err = s.Ledger.ConsensusVersion(ParamsRound(nextRound.Number), nextRound.Branch)
			if err != nil {
				s.log.Errorf("unable to retrieve consensus version for round %d: %v", ParamsRound(nextRound.Number), err)
				time.Sleep(time.Second)
				continue
			}

			break
		}

		if enablePipelining(nextVersion) {
			status = &pipelinePlayer{}
			status2 = &player{}
		} else {
			status = &player{}
		}

		router = makeRootRouter(status)
		router2 = makeRootRouter(status2)

		a = status.init(routerHandle{t: s.tracer, r: &router, src: status.T()}, nextRound, nextVersion)
		if enablePipelining(nextVersion) {
			status2.init(routerHandle{t: s.tracer, r: &router2, src: status2.T()}, nextRound, nextVersion)
		}
	} else {
		s.clockManager = clockManager
	}

	for {
		output <- a
		ready <- status.externalDemuxSignals()
		e, ok := <-input
		if !ok {
			break
		}

		var ac, ac2 actor
		ac, a = router.submitTop(s.tracer, status, e)
		status = ac.(serializableActor)

		if status2 != nil { // double-check by feeding event to status2
			ac2, a2 = router2.submitTop(s.tracer, status2, e)
			status2 = ac2.(serializableActor)

			if !reflect.DeepEqual(a, a2) {
				fmt.Printf("MISMATCHED ACTIONS: pipelinePlayer %+v\n", a)
				fmt.Printf("MISMATCHED ACTIONS: regular player %+v\n", a2)
			}
		}

		// XXXX only persist specific sub-player states when they return persistent actions
		if persistent(a) {
			s.persistRouter = router
			s.persistStatus = status
			s.persistActions = a
		}
	}
	close(output)
}

// persistState encodes the existing state of the agreement service and enqueue the
// encoded state to the persistence loop so it will get stored asynchronously.
// the done channel would get closed once operation complete successfully, or return an
// error if not.
// usage semantics : caller should ensure to call this function only when we have participation
// keys for the given voting round. // XXXX why
func (s *Service) persistState(round round, period period, step step, done chan error) (events <-chan externalEvent) {
	// get state of all players
	allRPS := s.persistStatus.allPlayersRPS()
	raw := encode(s.clockManager, s.persistRouter, s.persistStatus, s.persistActions)
	return s.persistenceLoop.Enqueue(s.clockManager, allRPS, RPS{Round: round, Period: period, Step: step}, raw, done)
}

func (s *Service) do(ctx context.Context, as []action) {
	for _, a := range as {
		a.do(ctx, s)
	}
}
