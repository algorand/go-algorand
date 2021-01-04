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
	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/logging"
)

//go:generate stringer -type=coserviceType
const (
	demuxCoserviceType coserviceType = iota
	tokenizerCoserviceType
	cryptoVerifierCoserviceType
	pseudonodeCoserviceType
	clockCoserviceType
	networkCoserviceType
)

//msgp:ignore coserviceType
type coserviceType int

type coserviceMonitor struct {
	deadlock.Mutex

	id int
	c  map[coserviceType]uint

	coserviceListener
}

type coserviceListener interface {
	inc(sum uint, state map[coserviceType]uint)
	dec(sum uint, state map[coserviceType]uint)
}

func (m *coserviceMonitor) inc(t coserviceType) {
	if m == nil {
		return
	}

	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	if m.c == nil {
		m.c = make(map[coserviceType]uint)
	}
	m.c[t]++

	if m.coserviceListener != nil {
		m.coserviceListener.inc(m.sum(), m.c)
	}
}

func (m *coserviceMonitor) dec(t coserviceType) {
	if m == nil {
		return
	}

	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	if m.c == nil {
		m.c = make(map[coserviceType]uint)
	}
	if m.c[t] == 0 {
		logging.Base().Panicf("%d: tried to decrement empty coservice queue %v", m.id, t)
	}
	m.c[t]--

	if m.coserviceListener != nil {
		m.coserviceListener.dec(m.sum(), m.c)
	}
}

func (m *coserviceMonitor) sum() (s uint) {
	for _, n := range m.c {
		s += n
	}
	return
}
