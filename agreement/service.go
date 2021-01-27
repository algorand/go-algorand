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
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/timers"
)

const (
	defaultCadaverName = "agreement"
)

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
	persistStatus  player
	persistActions []action
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
	timers.Clock
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
	CurrentRound         round
}

// MakeService creates a new Agreement Service instance given a set of Parameters.
//
// Call Start to start execution and Shutdown to finish execution.
func MakeService(p Parameters) *Service {
	s := new(Service)

	s.parameters = parameters(p)

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
	ready := make(chan externalDemuxSignals)
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
func (s *Service) demuxLoop(ctx context.Context, input chan<- externalEvent, output <-chan []action, ready <-chan externalDemuxSignals) {
	for a := range output {
		s.do(ctx, a)
		extSignals := <-ready
		e, ok := s.demux.next(s, extSignals.Deadline, extSignals.FastRecoveryDeadline, extSignals.CurrentRound)
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
func (s *Service) mainLoop(input <-chan externalEvent, output chan<- []action, ready chan<- externalDemuxSignals) {
	// setup
	var clock timers.Clock
	var router rootRouter
	var status player
	var a []action
	var err error
	raw, err := restore(s.log, s.Accessor)
	if err == nil {
		clock, router, status, a, err = decode(raw, s.Clock)
		if err != nil {
			reset(s.log, s.Accessor)
		} else {
			s.log.Infof("decode (agreement): restored crash state from database (pending %v @ %+v)", a, status)
		}
	}
	// err will tell us if the restore/decode operations above completed successfully or not.
	if err != nil || status.Round < s.Ledger.NextRound() {
		// in this case, we don't have fresh and valid state
		// pretend a new round has just started, and propose a block
		status = player{Round: s.Ledger.NextRound(), Step: soft, Deadline: FilterTimeout(0, protocol.ConsensusCurrentVersion)}
		router = makeRootRouter(status)

		a1 := pseudonodeAction{T: assemble, Round: s.Ledger.NextRound()}
		a2 := rezeroAction{}

		a = make([]action, 0)
		a = append(a, a1, a2)
	} else {
		s.Clock = clock
	}

	for {
		output <- a
		ready <- externalDemuxSignals{Deadline: status.Deadline, FastRecoveryDeadline: status.FastRecoveryDeadline, CurrentRound: status.Round}
		e, ok := <-input
		if !ok {
			break
		}

		status, a = router.submitTop(s.tracer, status, e)

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
// keys for the given voting round.
func (s *Service) persistState(done chan error) (events <-chan externalEvent) {
	raw := encode(s.Clock, s.persistRouter, s.persistStatus, s.persistActions)
	return s.persistenceLoop.Enqueue(s.Clock, s.persistStatus.Round, s.persistStatus.Period, s.persistStatus.Step, raw, done)
}

func (s *Service) do(ctx context.Context, as []action) {
	for _, a := range as {
		a.do(ctx, s)
	}
}
