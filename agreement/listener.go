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
	"github.com/algorand/go-algorand/logging"
)

// A listener is a state machine which can handle events, returning new events.
type listener interface {
	// T returns the stateMachineTag describing the listener.
	T() stateMachineTag

	// underlying returns a listener of the underlying type.
	//
	// This is used to get to the underlying type when it is wrapped by another type.
	// For instance, if
	//   c = checkedListener{listener: voteAggregator{}, listenerContract: voteAggregatorContract{}}
	// then
	//   c.underlying() == c.listener
	underlying() listener

	// handle an event, updating the state of the listener.
	handle(routerHandle, player, event) event
}

// A listenerContract describes the list of allowed preconditions and postconditions
// for events entering and exiting the listener.
type listenerContract interface {
	// pre returns an error for each precondition that is violated for each
	// event sent to some listener.
	pre(p player, in event) []error

	// post returns an error for each postcondition that is violated for
	// each event emitted by a listener.
	post(p player, in event, out event) []error
}

// A checkedListener wraps a listener, checking its contract on each call.
type checkedListener struct {
	listener
	listenerContract
}

func (l checkedListener) handle(r routerHandle, p player, in event) event {
	errs := l.pre(p, in)
	if len(errs) != 0 {
		for _, err := range errs {
			logging.Base().Errorf("%v: precondition violated: %v", l.T(), err)
		}
		logging.Base().Panicf("%v: precondition violated: %v", l.T(), errs[0])
	}
	out := l.listener.handle(r, p, in)
	errs = l.post(p, in, out)
	if len(errs) != 0 {
		for _, err := range errs {
			logging.Base().Errorf("%v: postcondition violated: %v", l.T(), err)
		}
		logging.Base().Panicf("%v: postcondition violated: %v", l.T(), errs[0])
	}
	return out
}
