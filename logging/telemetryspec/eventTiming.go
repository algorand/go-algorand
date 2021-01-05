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

package telemetryspec

import (
	"time"
)

// LocalMsgTiming contains timing for a single message type. The time is in int64 ns
// precision offsets (from some relevant time defined by context; normally, round start time).
type LocalMsgTiming struct {
	// LRFirst is the time a message type is first received. For this to
	// be useful we should test deployments with non-voting nodes.
	LRFirst *TimeWithSender `json:"lrfirst,omitempty"`

	// LRLast is the time a message type is last received (and not filtered).
	LRLast *TimeWithSender `json:"lrlast,omitempty"`

	// LStart is the step start time. We could derive from elsewhere.
	LStart *time.Duration `json:"lstart,omitempty"` // optional

	// LRWin is the time a "winning" message is received, defined for proposals/payloads.
	LRWin *TimeWithSender `json:"lrwin,omitempty"` // optional

	// LRThresh is the time a threshold is triggered locally.
	LRThresh *time.Duration `json:"lrtresh,omitempty"` // optional
}

// TimeWithSender contains a timestamp and message source.
type TimeWithSender struct {
	T      time.Duration `json:"t"`
	Sender string        `json:"sender"`
}
