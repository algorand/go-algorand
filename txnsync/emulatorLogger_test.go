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
	"fmt"
	"strings"

	"github.com/algorand/go-algorand/logging"
)

// Foreground text colors
const (
	reset     = 0
	black     = 30
	red       = 31
	green     = 32
	yellow    = 33
	blue      = 34
	magenta   = 35
	cyan      = 36
	white     = 37
	hiblack   = 90
	hired     = 91
	higreen   = 92
	hiyellow  = 93
	hiblue    = 94
	himagenta = 95
	hicyan    = 96
	hiwhite   = 97
)

const escape = "\x1b"

var colors = []int{red, green, yellow, blue, magenta, cyan, hired, higreen, hiyellow, hiblue, himagenta, hicyan}
var lowColors = []int{red, green, yellow, blue, magenta, cyan}

type emulatorNodeLogger struct {
	logging.Logger
	node        *emulatedNode
	longestName int
}

func makeNodeLogger(l logging.Logger, node *emulatedNode) logging.Logger {
	return &emulatorNodeLogger{
		Logger: l,
		node:   node,
	}
}

func (e emulatorNodeLogger) Infof(s string, args ...interface{}) {
	if s == incomingTxSyncMsgFormat || s == outgoingTxSyncMsgFormat {
		// special output.
		e.printMsg(s, args...)
	} else {
		e.Logger.Infof(e.node.name+" :"+s, args...)
	}
}

func (e emulatorNodeLogger) printMsg(s string, args ...interface{}) {
	// "Incoming Txsync #%d round %d transacations %d request [%d/%d]"
	var seq int
	var round int
	var transactions int
	var offset, modulator int
	var bloom int
	var nextTS int
	var destIndex int
	fmt.Sscanf(fmt.Sprintf("%v %v %v %v %v %v %v %v", args...), "%d %d %d %d %d %d %d %d", &seq, &round, &transactions, &offset, &modulator, &bloom, &nextTS, &destIndex)

	destName := e.node.emulator.nodes[destIndex].name

	if e.longestName == 0 {
		for _, node := range e.node.emulator.nodes {
			if len(node.name) > e.longestName {
				e.longestName = len(node.name) + 1
			}
		}
	}

	elapsed := e.node.emulator.clock.Since().Milliseconds()
	out := fmt.Sprintf("%3d.%03d ", elapsed/1000, elapsed%1000)
	if s == outgoingTxSyncMsgFormat {
		out += fmt.Sprintf("%"+fmt.Sprintf("%d", e.longestName)+"s", e.node.name)
	} else {
		out += fmt.Sprintf("%"+fmt.Sprintf("%d", e.longestName)+"s", destName)
	}
	bfColor := hiblack
	if bloom > 0 {
		bfColor = higreen
	}
	nextTSColor := hiblack
	if nextTS > 0 {
		nextTSColor = higreen
	}
	mid := fmt.Sprintf("Round %s Txns %s Req [%3d/%3d] %s %s",
		wrapRollingColor(round, fmt.Sprintf("%2d", round)),
		wrapRollingColor(transactions, fmt.Sprintf("%3d", transactions)),
		offset,
		modulator,
		wrapColor(bfColor, "BF"),
		wrapColor(nextTSColor, "TS"),
	)
	if s == incomingTxSyncMsgFormat {
		out += wrapColor(hiblack, " [ ")
		out += strings.Repeat(" ", 20) + wrapRollingLowColor(seq, " <-- ") + mid
		out += wrapRollingLowColor(seq, " ] ")
	} else {
		out += wrapRollingLowColor(seq, " [ ")
		out += mid + wrapRollingLowColor(seq, " --> ") + strings.Repeat(" ", 20)
		out += wrapColor(hiblack, " ] ")
	}

	if s == outgoingTxSyncMsgFormat {
		out += fmt.Sprintf("%"+fmt.Sprintf("%d", e.longestName)+"s", destName)
	} else {
		out += fmt.Sprintf("%"+fmt.Sprintf("%d", e.longestName)+"s", e.node.name)
	}
	fmt.Printf("%s\n", out)
}

func wrapRollingLowColor(color int, s string) (out string) {
	return wrapColor(lowColors[color%len(lowColors)], s)
}

func wrapRollingColor(color int, s string) (out string) {
	return wrapColor(colors[color%len(colors)], s)
}
func wrapColor(color int, s string) (out string) {
	return fmt.Sprintf("%s[1;%dm%s%s[1;%dm", escape, color, s, escape, reset)
}
