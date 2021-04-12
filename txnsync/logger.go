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

package txnsync

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
)

// make a local alias of the type so that we can refer to it without '.'
type algodlogger = logging.Logger

type msgStats struct {
	sequenceNumber  uint64
	round           basics.Round
	transactions    int
	offsetModulator requestParams
	bloomSize       int
	nextMsgMinDelay uint64
	peerAddress     string
}

type msgLogger interface {
	outgoingMessage(mstat msgStats)
	incomingMessage(mstat msgStats)
}

// Logger is go-algorand/logging.Logger with some private additions for txnsync
type Logger interface {
	logging.Logger
	msgLogger
}

type basicMsgLogger struct {
	algodlogger
}

func wrapLogger(l logging.Logger) Logger {
	if ll, ok := l.(Logger); ok {
		return ll
	}
	out := new(basicMsgLogger)
	out.algodlogger = l
	return out
}

func (l *basicMsgLogger) logMessage(mstat msgStats, mode, tofrom string) {
	l.Debugf(
		"%s Txsync #%d round %d transacations %d request [%d/%d] bloom %d nextTS %d %s '%s'",
		mode,
		mstat.sequenceNumber,
		mstat.round,
		mstat.transactions,
		mstat.offsetModulator.Offset,
		mstat.offsetModulator.Modulator,
		mstat.bloomSize,
		mstat.nextMsgMinDelay,
		tofrom,
		mstat.peerAddress,
	)
}
func (l *basicMsgLogger) outgoingMessage(mstat msgStats) {
	l.logMessage(mstat, "Outgoing", "to")
}
func (l *basicMsgLogger) incomingMessage(mstat msgStats) {
	l.logMessage(mstat, "Incoming", "from")
}
