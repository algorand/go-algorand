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

import (
	"fmt"
)

// An actor is a state machine which accepts events and returns sequences of actions.
type actor interface {
	// T returns the stateMachineTag describing the actor.
	T() stateMachineTag

	// underlying returns an actor of the underlying type.
	//
	// This is used to get to the underlying type when it is wrapped by another type.
	// For instance, if
	//   c = checkedActor{actor: player{}, actorContract: playerContract{}}
	// then
	//   c.underlying() == c.actor
	underlying() actor

	// handle an event, updating the state of the actor.
	//
	// handle should return a sequence of actions to be performed given the event.
	handle(routerHandle, event) []action
}

// An actorContract describes the list of allowed preconditions and postconditions
// for events entering and exiting the actor.
type actorContract interface {
	// call returns errors for each precondition and each postcondition
	// that is violated as an actor handles an event.
	//
	// in represents the event that the actor accepted,
	// while out represents the sequence of actions that the actor emitted.
	call(aold, anew actor, in event, out []action) (pre, post []error)

	// trace returns errors for each precondition and each postcondition
	// that is violated for an actor handling a sequence of events.
	//
	// in represents the sequence of events that the actor accepted,
	// while out represents the sequence of action sequences that the actor emitted.
	//
	// len(in) == len(out), while the lengths of the individual slices in out
	// are the number of actions taken for the corresponding input events.
	trace(aold, anew []actor, in []event, out [][]action) (pre, post []error)
}

// A checkedActor wraps an actor, checking its contract on each call.
//
type checkedActor struct {
	actor
	actorContract

	//   a   []actor
	//   in  []event
	//   out [][]action
}

func (l checkedActor) handle(r routerHandle, in event) []action {
	aold := *l.underlying().(*player)
	out := l.actor.handle(r, in)
	anew := *l.underlying().(*player)

	//   lout.p = append(l.p, p)
	//   lout.in = append(l.in, in)
	//   lout.out = append(l.out, out)

	// check against contract
	cerrpre, cerrpost := l.call(&aold, &anew, in, out)
	//   terrpre, terrpost := lout.trace(lout.p, lout.in, lout.out)

	for _, pre := range cerrpre {
		if pre != nil {
			r.t.log.Warnf("precondition call violation: %v", pre)
		}
	}
	for _, post := range cerrpost {
		if post != nil {
			r.t.log.Warnf("postcondition call violation: %v", post)
		}
	}
	//   for _, pre := range terrpre {
	//   	if pre != nil {
	//   		logging.Base().Warnf("precondition trace violation: %v", pre)
	//   	}
	//   }
	//   for _, post := range terrpost {
	//   	if post != nil {
	//   		logging.Base().Warnf("postcondition trace violation: %v", post)
	//   	}
	//   }

	return out
}

//   func (l checkedActor) traceString() string {
//   	var res string
//   	for i := range l.in {
//   		in := l.in[i]
//   		out := l.out[i]

//   		var tags []string
//   		for _, a := range out {
//   			tags = append(tags, a.String())
//   		}
//   		outstr := strings.Join(tags, ", ")

//   		res += fmt.Sprintf("%v\t%v\n", in.t(), outstr)
//   	}
//   	return res
//   }

type ioLoggedActor struct {
	checkedActor
	tracer tracer
}

func (l ioLoggedActor) handle(h routerHandle, e event) []action {
	if l.tracer.level >= top {
		fmt.Fprintf(l.tracer.w, "%23v  => %23v: %v\n", "", l.T(), e)
	}
	a := l.checkedActor.handle(h, e)
	if l.tracer.level >= top {
		fmt.Fprintf(l.tracer.w, "%23v <=  %23v: %v\n", "", l.T(), a)
	}
	return a
}
