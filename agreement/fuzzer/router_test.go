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
	"github.com/algorand/go-algorand/protocol"
)

// Router is the core router which delivers all messages between the nodes.
type Router struct {
	DownstreamFilter
	fuzzer   *Fuzzer
	q        []routedMessage
	activity int32
}

type routedMessage struct {
	tag      protocol.Tag
	data     []byte
	source   int
	target   int
	upstream UpstreamFilter
}

// MakeRouter creates a router
func MakeRouter(fuzzer *Fuzzer) *Router {
	r := &Router{
		fuzzer: fuzzer,
		q:      make([]routedMessage, 0),
	}
	return r
}

func (r *Router) getUpstreamFilter(targetNode int) (upstreamFilter UpstreamFilter) {
	currentFilter := DownstreamFilter(r.fuzzer.facades[targetNode])
	// go down the stream until we get to the router, and
	for {
		downstreamFilter := currentFilter.GetDownstreamFilter()

		if downstreamFilter == DownstreamFilter(r) {
			// we've reached the router. we need to go one step back.
			upstreamFilter, _ = currentFilter.(UpstreamFilter)
			return
		}
		currentFilter = downstreamFilter
	}
}

// SendMessage routes messages sent to message received.
func (r *Router) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	if targetNode >= 0 {
		r.sendMessageToNode(sourceNode, targetNode, tag, data)
		return
	}
	for i := 0; i < r.fuzzer.nodesCount; i++ {
		if i != sourceNode {
			r.sendMessageToNode(sourceNode, i, tag, data)
		}
	}
}

// GetDownstreamFilter implementation.
func (r *Router) GetDownstreamFilter() DownstreamFilter {
	return nil
}

// SendMessage routes messages sent to message received.
func (r *Router) sendMessageToNode(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	upstreamFilter := r.getUpstreamFilter(targetNode)
	if upstreamFilter == nil {
		return
	}
	if r.fuzzer.IsDisconnected(sourceNode, targetNode) {
		return
	}

	r.q = append(r.q, routedMessage{
		tag:      tag,
		data:     data,
		source:   sourceNode,
		target:   targetNode,
		upstream: upstreamFilter,
	})
}

func (r *Router) Start() {
}

func (r *Router) Shutdown() {
}

func (r *Router) sendMessage(targetNode int, tag protocol.Tag) bool {
	if len(r.q) == 0 {
		return false
	}
	for i, msg := range r.q {
		if msg.target == targetNode {
			if tag != "" && msg.tag != tag {
				continue
			}
			r.q = append(r.q[:i], r.q[i+1:]...)
			msg.upstream.ReceiveMessage(msg.source, msg.tag, msg.data)
			return true
		}
	}

	return false
}

func (r *Router) hasPendingMessage(targetNode int, tag protocol.Tag) bool {
	if len(r.q) == 0 {
		return false
	}
	for _, msg := range r.q {
		if msg.target == targetNode {
			if tag != "" && msg.tag != tag {
				continue
			}
			return true
		}
	}

	return false
}

// Tick send clock updates across all the filters.
func (r *Router) Tick(newClockTime int) bool {
	changed := false
	for i := 0; i < r.fuzzer.nodesCount; i++ {
		up := r.getUpstreamFilter(i)
		changed = up.Tick(newClockTime) || changed
	}
	return changed
}
