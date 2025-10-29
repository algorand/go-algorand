// Copyright (C) 2019-2025 Algorand, Inc.
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
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

type VoteFilterMask struct {
	StartRound, EndRound   basics.Round
	StartPeriod, EndPeriod period
	StartStep, EndStep     step
}

type VoteFilterConfig struct {
	IncludeMasks  []VoteFilterMask
	ExcludeMasks  []VoteFilterMask
	DebugMessages bool
}

type VoteFilter struct {
	NetworkFilter
	upstream   UpstreamFilter
	downstream DownstreamFilter
	fuzzer     *Fuzzer
	nodeID     int

	NetworkFilterFactory
	config *VoteFilterConfig
}

func (n *VoteFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	if n.Eval(tag, data, "S") {
		n.downstream.SendMessage(sourceNode, targetNode, tag, data)
	}
}

func (n *VoteFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *VoteFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	if n.Eval(tag, data, "R") {
		n.upstream.ReceiveMessage(sourceNode, tag, data)
	}
}

func (n *VoteFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *VoteFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *VoteFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	return &VoteFilter{
		config: n.config,
		fuzzer: fuzzer,
		nodeID: nodeID,
	}
}

func (n *VoteFilter) Tick(newClockTime int) bool {
	return n.upstream.Tick(newClockTime)
}

func MakeVoteFilter(voteFilterConfig *VoteFilterConfig) *VoteFilter {
	return &VoteFilter{
		config: voteFilterConfig,
	}
}
func (n *VoteFilter) Eval(tag protocol.Tag, data []byte, direction string) bool {
	msgDecoder := n.fuzzer.facades[n.nodeID].GetFilterByType(reflect.TypeFor[*MessageDecoderFilter]()).(*MessageDecoderFilter)
	if msgDecoder == nil {
		return true
	}
	uv, _, _ := msgDecoder.getDecodedMessage(tag, data)
	if uv == nil {

		return true
	}

	included := false
	for _, mask := range n.config.IncludeMasks {
		if mask.StartRound <= uv.R.Round && mask.EndRound >= uv.R.Round &&
			mask.StartPeriod <= uv.R.Period && mask.EndPeriod >= uv.R.Period &&
			mask.StartStep <= uv.R.Step && mask.EndStep >= uv.R.Step {
			included = true
			break
		}
	}
	if !included {
		if n.config.DebugMessages {
			fmt.Printf("VoteFilter(%s) service-%v : (%d,%d,%d) skipped. Rules (%d-%d, %d-%d, %d-%d)\n", direction, n.nodeID, uv.R.Round, uv.R.Period, uv.R.Step, n.config.IncludeMasks[0].StartRound, n.config.IncludeMasks[0].EndRound, n.config.IncludeMasks[0].StartPeriod, n.config.IncludeMasks[0].EndPeriod, n.config.IncludeMasks[0].StartStep, n.config.IncludeMasks[0].EndStep)
		}
		return false
	}

	excluded := false
	for _, mask := range n.config.ExcludeMasks {
		if mask.StartRound <= uv.R.Round && mask.EndRound >= uv.R.Round &&
			mask.StartPeriod <= uv.R.Period && mask.EndPeriod >= uv.R.Period &&
			mask.StartStep <= uv.R.Step && mask.EndStep >= uv.R.Step {
			excluded = true
			break
		}
	}

	if excluded {
		if n.config.DebugMessages {
			fmt.Printf("VoteFilter(%s) service-%v : (%d,%d,%d) skipped\n", direction, n.nodeID, uv.R.Round, uv.R.Period, uv.R.Step)
		}
		return false
	}

	if n.config.DebugMessages {
		fmt.Printf("VoteFilter(%s) service-%v : (%d,%d,%d) passed\n", direction, n.nodeID, uv.R.Round, uv.R.Period, uv.R.Step)
	}
	return true
}

// Unmarshall VoteFilter
func (n *VoteFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type voteFilterJSON struct {
		Name             string
		VoteFilterConfig VoteFilterConfig
	}

	var jsonConfig voteFilterJSON
	if err := json.Unmarshal(b, &jsonConfig); err != nil {
		return nil
	}
	if jsonConfig.Name != "VoteFilterJSON" {
		return nil
	}

	return MakeVoteFilter(&jsonConfig.VoteFilterConfig)
}

// register VoteFilter
func init() {
	registeredFilterFactories = append(registeredFilterFactories, &VoteFilter{})
}
