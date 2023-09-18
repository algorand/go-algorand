// Copyright (C) 2019-2023 Algorand, Inc.
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

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/logspec"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/timers"
)

// diskState represents the state required by the agreement protocol to be persistent.
type diskState struct {
	_struct struct{} `codec:","`

	Router []byte
	Player []byte
	Clock  []byte

	ActionTypes []actionType `codec:"ActionTypes,allocbound=-"`
	Actions     [][]byte     `codec:"Actions,allocbound=-"`
}

func persistent(as []action) bool {
	for _, a := range as {
		if a.persistent() {
			return true
		}
	}
	return false
}

// encode serializes the current state into a byte array.
func encode(t timers.Clock[TimeoutType], rr rootRouter, p player, a []action, reflect bool) (raw []byte) {
	var s diskState

	// Don't persist state for old rounds
	// rootRouter.update() may preserve roundRouters from credentialRoundLag rounds ago
	children := make(map[round]*roundRouter)
	for rnd, rndRouter := range rr.Children {
		if rnd >= p.Round {
			children[rnd] = rndRouter
		}
	}
	rr.Children = children

	if reflect {
		s.Router = protocol.EncodeReflect(rr)
		s.Player = protocol.EncodeReflect(p)
	} else {
		s.Router = protocol.Encode(&rr)
		s.Player = protocol.Encode(&p)
	}
	s.Clock = t.Encode()
	s.ActionTypes = make([]actionType, len(a))
	s.Actions = make([][]byte, len(a))
	for i, act := range a {
		s.ActionTypes[i] = act.t()

		// still use reflection for actions since action is an interface and we can't define marshaller methods on it
		s.Actions[i] = protocol.EncodeReflect(act)
	}
	if reflect {
		raw = protocol.EncodeReflect(s)
	} else {
		raw = protocol.Encode(&s)
	}
	return
}

// persist atomically writes state to the crash database.
func persist(log serviceLogger, crash db.Accessor, Round basics.Round, Period period, Step step, raw []byte) (err error) {
	logEvent := logspec.AgreementEvent{
		Type:   logspec.Persisted,
		Round:  uint64(Round),
		Period: uint64(Period),
		Step:   uint64(Step),
	}
	defer func() {
		log.with(logEvent).Info("persisted state to the database")
	}()

	err = crash.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("insert or replace into Service (rowid, data) values (1, ?)", raw)
		return err
	})
	if err == nil {
		return
	}

	log.Errorf("persisting failure: %v", err)
	return
}

// reset deletes the existing recovery state from database.
//
// In case it's unable to clear the Service table, an error would get logged.
func reset(log logging.Logger, crash db.Accessor) {
	log.Infof("reset (agreement): resetting crash state")

	err := crash.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		// we could not retrieve our state, so wipe it
		_, err = tx.Exec("delete from Service")
		return
	})

	if err != nil {
		log.Warnf("reset (agreement): failed to clear Service table - %v", err)
	}
}

// errNoCrashStateAvailable returned by restore when the crash recovery state is not available in the crash recovery database table.
var errNoCrashStateAvailable = errors.New("restore (agreement): no crash state available")

// restore reads state from a crash database. It does not attempt to parse the encoded data.
//
// It returns an error if this fails or if crash state does not exist.
func restore(log logging.Logger, crash db.Accessor) (raw []byte, err error) {
	var noCrashState bool
	defer func() {
		if err != nil && !noCrashState {
			log.Warnf("restore (agreement): could not restore crash state from database: %v", err)
		}
	}()

	err = crash.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return agreeInstallDatabase(tx)
	})

	if err == nil {
		// the above call was completed sucecssfully, which means that we've just created the table ( which wasn't there ! ).
		// in that case, the table is guaranteed to be empty, and therefore we can return right here.
		log.Infof("restore (agreement): crash state table initialized")
		noCrashState = true // this is a normal case (we don't have crash state)
		err = errNoCrashStateAvailable
		return
	}

	err = crash.Atomic(func(ctx context.Context, tx *sql.Tx) (res error) {
		var reset bool
		defer func() {
			if !reset {
				return
			}
			log.Infof("restore (agreement): resetting crash state")

			// we could not retrieve our state, so wipe it
			_, err = tx.Exec("delete from Service")
			if err != nil {
				res = fmt.Errorf("restore (agreement): (in reset) failed to clear Service table")
				return
			}
		}()

		var nrows int
		row := tx.QueryRow("select count(*) from Service")
		err := row.Scan(&nrows)
		if err != nil {
			log.Errorf("restore (agreement): could not query raw state: %v", err)
			reset = true
			return err
		}
		if nrows != 1 {
			log.Infof("restore (agreement): crash state not found (n = %d)", nrows)
			reset = true
			noCrashState = true // this is a normal case (we have leftover crash state from an old round)
			return errNoCrashStateAvailable
		}

		row = tx.QueryRow("select data from Service")
		err = row.Scan(&raw)
		if err != nil {
			log.Errorf("restore (agreement): could not read crash state raw data: %v", err)
			reset = true
			return err
		}

		return nil
	})
	return
}

// decode process the incoming raw bytes array and attempt to reconstruct the agreement state objects.
//
// In all decoding errors, it returns the error code in err
func decode(raw []byte, t0 timers.Clock[TimeoutType], log serviceLogger, reflect bool) (t timers.Clock[TimeoutType], rr rootRouter, p player, a []action, err error) {
	var t2 timers.Clock[TimeoutType]
	var rr2 rootRouter
	var p2 player
	a2 := []action{}
	var s diskState
	if reflect {
		err = protocol.DecodeReflect(raw, &s)
		if err != nil {
			log.Errorf("decode (agreement): error decoding retrieved state (len = %v): %v", len(raw), err)
			return
		}
	} else {
		err = protocol.Decode(raw, &s)
		if err != nil {
			log.Warnf("decode (agreement): error decoding retrieved state using msgp (len = %v): %v. Trying reflection", len(raw), err)
			err = protocol.DecodeReflect(raw, &s)
			if err != nil {
				log.Errorf("decode (agreement): error decoding using either reflection or msgp): %v", err)
				return
			}
		}
	}

	t2, err = t0.Decode(s.Clock)
	if err != nil {
		return
	}

	if reflect {
		err = protocol.DecodeReflect(s.Player, &p2)
		if err != nil {
			return
		}
		p2.lowestCredentialArrivals = makeCredentialArrivalHistory(dynamicFilterCredentialArrivalHistory)
		rr2 = makeRootRouter(p2)
		err = protocol.DecodeReflect(s.Router, &rr2)
		if err != nil {
			return
		}
	} else {
		err = protocol.Decode(s.Player, &p2)
		if err != nil {
			log.Warnf("decode (agreement): failed to decode Player using msgp (len = %v): %v. Trying reflection", len(s.Player), err)
			err = protocol.DecodeReflect(s.Player, &p2)
			if err != nil {
				log.Errorf("decode (agreement): failed to decode Player using either reflection or msgp: %v", err)
				return
			}
		}
		p2.lowestCredentialArrivals = makeCredentialArrivalHistory(dynamicFilterCredentialArrivalHistory)
		if p2.OldDeadline != 0 {
			p2.Deadline = Deadline{Duration: p2.OldDeadline, Type: TimeoutDeadline}
			p2.OldDeadline = 0 // clear old value
		}
		rr2 = makeRootRouter(p2)
		err = protocol.Decode(s.Router, &rr2)
		if err != nil {
			log.Warnf("decode (agreement): failed to decode Router using msgp (len = %v): %v. Trying reflection", len(s.Router), err)
			rr2 = makeRootRouter(p2)
			err = protocol.DecodeReflect(s.Router, &rr2)
			if err != nil {
				log.Errorf("decode (agreement): failed to decode Router using either reflection or msgp: %v", err)
				return
			}
		}
	}

	for i := range s.Actions {
		act := zeroAction(s.ActionTypes[i])
		// always use reflection for actions since action is an interface and we can't define unmarshaller methods on it
		err = protocol.DecodeReflect(s.Actions[i], &act)
		if err != nil {
			return
		}
		a2 = append(a2, act)
	}

	t = t2
	rr = rr2
	p = p2
	a = a2
	return
}

type persistentRequest struct {
	round  basics.Round
	period period
	step   step
	raw    []byte
	done   chan error
	clock  timers.Clock[TimeoutType]
	events chan<- externalEvent
}

type asyncPersistenceLoop struct {
	log     serviceLogger
	crashDb db.Accessor
	ledger  LedgerReader
	wg      sync.WaitGroup // wait for goroutine to abort.
	ctxExit context.CancelFunc
	pending chan persistentRequest
}

func makeAsyncPersistenceLoop(log serviceLogger, crash db.Accessor, ledger LedgerReader) *asyncPersistenceLoop {
	return &asyncPersistenceLoop{
		log:     log,
		crashDb: crash,
		ledger:  ledger,
		pending: make(chan persistentRequest, 1),
	}
}

func (p *asyncPersistenceLoop) Enqueue(clock timers.Clock[TimeoutType], round basics.Round, period period, step step, raw []byte, done chan error) (events <-chan externalEvent) {
	eventsChannel := make(chan externalEvent, 1)
	p.pending <- persistentRequest{
		round:  round,
		period: period,
		step:   step,
		raw:    raw,
		done:   done,
		clock:  clock,
		events: eventsChannel,
	}
	return eventsChannel
}

func (p *asyncPersistenceLoop) Start() {
	p.wg.Add(1)
	ctx, ctxExit := context.WithCancel(context.Background())
	p.ctxExit = ctxExit
	go p.loop(ctx)
}

func (p *asyncPersistenceLoop) Quit() {
	p.ctxExit()
	p.wg.Wait()
}

func (p *asyncPersistenceLoop) loop(ctx context.Context) {
	defer p.wg.Done()
	var s persistentRequest
	for {
		select {
		case <-ctx.Done():
			return
		case s, _ = <-p.pending:
		}

		// make sure that the ledger finished writing the previous round to disk.
		select {
		case <-ctx.Done():
			return
		case <-p.ledger.Wait(s.round.SubSaturate(1)):
		}

		// store the state.
		err := persist(p.log, p.crashDb, s.round, s.period, s.step, s.raw)

		s.events <- checkpointEvent{
			Round:  s.round,
			Period: s.period,
			Step:   s.step,
			Err:    makeSerErr(err),
			done:   s.done,
		}
		close(s.events)

		// sanity check; we check it after the fact, since it's not expected to ever happen.
		// performance-wise, it takes approximitly 300000ns to execute, and we don't want it to
		// block the persist operation.
		_, _, _, _, derr := decode(s.raw, s.clock, p.log, false)
		if derr != nil {
			p.log.Errorf("could not decode own encoded disk state: %v", derr)
		}
	}
}
