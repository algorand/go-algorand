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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

type TrafficStatisticsFilterConfig struct {
	OutputFormat int
}

type TrafficMetric struct {
	Count int
	Bytes int
}

type TrafficStatisticsFilter struct {
	NetworkFilter
	ShutdownFilter

	upstream   UpstreamFilter
	downstream DownstreamFilter
	nodeID     int
	fuzzer     *Fuzzer
	factory    *TrafficStatisticsFilterFactory

	totalSentMessage              TrafficMetric
	totalReceivedMessage          TrafficMetric
	lastTick                      int
	firstNextRound, lastNextRound basics.Round
	tickOutgoingTraffic           map[int]*TrafficMetric
	tickIncomingTraffic           map[int]*TrafficMetric
	roundOutgoingTraffic          map[basics.Round]*TrafficMetric
	roundIncomingTraffic          map[basics.Round]*TrafficMetric
	incomingDuplicateMessage      TrafficMetric
	seenIncomingMessages          map[[sha256.Size]byte]bool
	outputFormat                  int
}

type TrafficStatisticsFilterFactory struct {
	NetworkFilterFactory
	nodes      map[int]*TrafficStatisticsFilter // maps nodeID -> filter
	gatherOnce bool
	fuzzer     *Fuzzer

	totalSentMessage              TrafficMetric
	totalReceivedMessage          TrafficMetric
	lastTick                      int
	firstNextRound, lastNextRound basics.Round
	tickOutgoingTraffic           map[int]*TrafficMetric
	tickIncomingTraffic           map[int]*TrafficMetric
	roundOutgoingTraffic          map[basics.Round]*TrafficMetric
	roundIncomingTraffic          map[basics.Round]*TrafficMetric
	incomingDuplicateMessage      TrafficMetric
	outputFormat                  int
	printHeader                   bool
}

func (t *TrafficMetric) IncreaseMetric(count int, bytes int) {
	t.Count += count
	t.Bytes += bytes
}

func (n *TrafficStatisticsFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	multiplier := 1
	if targetNode < 0 {
		multiplier = n.fuzzer.nodesCount - 1
	}

	n.totalSentMessage.IncreaseMetric(multiplier, multiplier*(len(data)+len(tag)))
	if _, has := n.tickOutgoingTraffic[n.lastTick]; !has {
		n.tickOutgoingTraffic[n.lastTick] = &TrafficMetric{}
	}
	n.tickOutgoingTraffic[n.lastTick].IncreaseMetric(multiplier, multiplier*(len(data)+len(tag)))

	nextRound := n.fuzzer.ledgers[n.nodeID].NextRound()
	if _, has := n.roundOutgoingTraffic[nextRound]; !has {
		n.roundOutgoingTraffic[nextRound] = &TrafficMetric{}
	}
	n.roundOutgoingTraffic[nextRound].IncreaseMetric(multiplier, multiplier*(len(data)+len(tag)))

	n.downstream.SendMessage(sourceNode, targetNode, tag, data)
}

func (n *TrafficStatisticsFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *TrafficStatisticsFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	n.totalReceivedMessage.IncreaseMetric(1, len(data)+len(tag))

	if _, has := n.tickIncomingTraffic[n.lastTick]; !has {
		n.tickIncomingTraffic[n.lastTick] = &TrafficMetric{}
	}
	n.tickIncomingTraffic[n.lastTick].IncreaseMetric(1, len(data)+len(tag))

	nextRound := n.fuzzer.ledgers[n.nodeID].NextRound()
	if _, has := n.roundIncomingTraffic[nextRound]; !has {
		n.roundIncomingTraffic[nextRound] = &TrafficMetric{}
	}
	n.roundIncomingTraffic[nextRound].IncreaseMetric(1, len(data)+len(tag))

	digest := sha256.Sum256(data)
	if n.seenIncomingMessages[digest] {
		n.incomingDuplicateMessage.IncreaseMetric(1, len(data))
	} else {
		n.seenIncomingMessages[digest] = true
	}

	n.upstream.ReceiveMessage(sourceNode, tag, data)
}

func (n *TrafficStatisticsFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *TrafficStatisticsFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *TrafficStatisticsFilter) Tick(newClockTime int) bool {
	if n.firstNextRound == 0 {
		n.firstNextRound = n.fuzzer.ledgers[n.nodeID].NextRound()
	}

	deltaTicks := newClockTime - n.lastTick
	if deltaTicks > 1 && n.tickIncomingTraffic[n.lastTick] != nil {
		// break the statistics of tickIncomingTraffic into multiple buckets.
		n.tickIncomingTraffic[n.lastTick].Count /= deltaTicks
		n.tickIncomingTraffic[n.lastTick].Bytes /= deltaTicks
		for i := n.lastTick; i < newClockTime; i++ {
			n.tickIncomingTraffic[i] = &TrafficMetric{
				Count: n.tickIncomingTraffic[n.lastTick].Count,
				Bytes: n.tickIncomingTraffic[n.lastTick].Bytes,
			}
		}
	}
	n.lastTick = newClockTime
	return n.upstream.Tick(newClockTime)
}

func ByteCountBinary(b int) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func getTrafficRanges(v []*TrafficMetric) (lowCount, highCount, lowBytes, highBytes int) {
	if len(v) == 0 {
		return
	}
	lowCount, highCount = v[0].Count, v[0].Count
	lowBytes, highBytes = v[0].Bytes, v[0].Bytes
	for _, t := range v {
		if t.Count < lowCount {
			lowCount = t.Count
		}
		if t.Count > highCount {
			highCount = t.Count
		}
		if t.Bytes < lowBytes {
			lowBytes = t.Bytes
		}
		if t.Bytes > highBytes {
			highBytes = t.Bytes
		}
	}

	return
}

func getTickTrafficRanges(m map[int]*TrafficMetric) (lowCount, highCount, lowBytes, highBytes int) {
	v := []*TrafficMetric{}

	for _, t := range m {
		v = append(v, t)
	}

	return getTrafficRanges(v)
}

func getRoundTrafficRanges(m map[basics.Round]*TrafficMetric) (lowCount, highCount, lowBytes, highBytes int) {
	v := []*TrafficMetric{}

	for _, t := range m {
		v = append(v, t)
	}

	return getTrafficRanges(v)
}

func (n *TrafficStatisticsFilter) PreShutdown() {
	n.factory.PreShutdown()
	n.lastNextRound = n.fuzzer.ledgers[n.nodeID].NextRound()

	switch n.outputFormat {
	case 1:
		fmt.Printf("Node %d statistics:\n", n.nodeID)
		fmt.Printf("Total Messages Sent : %d\n", n.totalSentMessage.Count)
		fmt.Printf("Total Outgoing Traffic : %s\n", ByteCountBinary(n.totalSentMessage.Bytes))
		lowTickCount, highTickCount, lowTickBytes, highTickBytes := getTickTrafficRanges(n.tickOutgoingTraffic)
		fmt.Printf("Outgoing Messages per tick : [%d...%d]\n", lowTickCount, highTickCount)
		fmt.Printf("Outgoing Traffic : [%s/tick...%s/tick] [%s/sec...%s/sec]\n", ByteCountBinary(lowTickBytes), ByteCountBinary(highTickBytes), ByteCountBinary(int(time.Duration(lowTickBytes)*time.Second/n.fuzzer.tickGranularity)), ByteCountBinary(int(time.Duration(highTickBytes)*time.Second/n.fuzzer.tickGranularity)))
		lowRoundCount, highRoundCount, lowRoundBytes, highRoundBytes := getRoundTrafficRanges(n.roundOutgoingTraffic)
		fmt.Printf("Outgoing Messages per round : [%d...%d]\n", lowRoundCount, highRoundCount)
		fmt.Printf("Outgoing Traffic per round : [%s...%s]\n", ByteCountBinary(lowRoundBytes), ByteCountBinary(highRoundBytes))

		fmt.Printf("Total Messages Received : %d\n", n.totalReceivedMessage.Count)
		fmt.Printf("Total Incoming Traffic : %s\n", ByteCountBinary(n.totalReceivedMessage.Bytes))
		lowTickCount, highTickCount, lowTickBytes, highTickBytes = getTickTrafficRanges(n.tickIncomingTraffic)
		fmt.Printf("Incoming Messages per tick : [%d...%d]\n", lowTickCount, highTickCount)
		fmt.Printf("Incoming Traffic : [%s/tick...%s/tick] [%s/sec...%s/sec]\n", ByteCountBinary(lowTickBytes), ByteCountBinary(highTickBytes), ByteCountBinary(int(time.Duration(lowTickBytes)*time.Second/n.fuzzer.tickGranularity)), ByteCountBinary(int(time.Duration(highTickBytes)*time.Second/n.fuzzer.tickGranularity)))
		lowRoundCount, highRoundCount, lowRoundBytes, highRoundBytes = getRoundTrafficRanges(n.roundIncomingTraffic)
		fmt.Printf("Incoming Messages per round : [%d...%d]\n", lowRoundCount, highRoundCount)
		fmt.Printf("Incoming Traffic per round : [%s...%s]\n", ByteCountBinary(lowRoundBytes), ByteCountBinary(highRoundBytes))

		fmt.Printf("Total Rounds : %d\n", n.lastNextRound-n.firstNextRound)

		fmt.Printf("\n")
	case 2:
		lowTickCount, highTickCount, lowTickBytes, highTickBytes := getTickTrafficRanges(n.tickOutgoingTraffic)
		lowRcvTickCount, highRcvTickCount, lowRcvTickBytes, highRcvTickBytes := getTickTrafficRanges(n.tickIncomingTraffic)
		fmt.Printf("%4d%6d%8d%11s%5d-%5d%11s-%10s%8d%11s%5d-%5d%11s-%10s%5d%%",
			n.nodeID,
			n.lastNextRound,
			n.totalSentMessage.Count,
			ByteCountBinary(n.totalSentMessage.Bytes),
			time.Duration(lowTickCount)*time.Second/n.fuzzer.tickGranularity,
			time.Duration(highTickCount)*time.Second/n.fuzzer.tickGranularity,
			ByteCountBinary(int(time.Duration(lowTickBytes)*time.Second/n.fuzzer.tickGranularity)),
			ByteCountBinary(int(time.Duration(highTickBytes)*time.Second/n.fuzzer.tickGranularity)),
			n.totalReceivedMessage.Count,
			ByteCountBinary(n.totalReceivedMessage.Bytes),
			time.Duration(lowRcvTickCount)*time.Second/n.fuzzer.tickGranularity,
			time.Duration(highRcvTickCount)*time.Second/n.fuzzer.tickGranularity,
			ByteCountBinary(int(time.Duration(lowRcvTickBytes)*time.Second/n.fuzzer.tickGranularity)),
			ByteCountBinary(int(time.Duration(highRcvTickBytes)*time.Second/n.fuzzer.tickGranularity)),
			n.incomingDuplicateMessage.Count*100/n.totalReceivedMessage.Count)
		fmt.Printf("\n")
	default:
	}

}

func (n *TrafficStatisticsFilter) PostShutdown() {
	n.factory.Gather()
}

func (n *TrafficStatisticsFilterFactory) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	f := &TrafficStatisticsFilter{
		nodeID:               nodeID,
		fuzzer:               fuzzer,
		factory:              n,
		tickOutgoingTraffic:  make(map[int]*TrafficMetric),
		tickIncomingTraffic:  make(map[int]*TrafficMetric),
		roundOutgoingTraffic: make(map[basics.Round]*TrafficMetric),
		roundIncomingTraffic: make(map[basics.Round]*TrafficMetric),
		seenIncomingMessages: make(map[[sha256.Size]byte]bool),
		outputFormat:         n.outputFormat,
	}
	n.fuzzer = fuzzer
	n.nodes[nodeID] = f

	return f
}
func (n *TrafficStatisticsFilterFactory) Print() {
	switch n.outputFormat {
	case 1:
		fmt.Printf("Network statistics:\n")

		fmt.Printf("Total Messages Sent : %d\n", n.totalSentMessage.Count)
		fmt.Printf("Total Outgoing Traffic : %s\n", ByteCountBinary(n.totalSentMessage.Bytes))
		lowTickCount, highTickCount, lowTickBytes, highTickBytes := getTickTrafficRanges(n.tickOutgoingTraffic)
		fmt.Printf("Outgoing Messages per tick : [%d...%d]\n", lowTickCount, highTickCount)
		fmt.Printf("Outgoing Traffic : [%s/tick...%s/tick] [%s/sec...%s/sec]\n",
			ByteCountBinary(lowTickBytes),
			ByteCountBinary(highTickBytes),
			ByteCountBinary(int(time.Duration(lowTickBytes)*time.Second/n.fuzzer.tickGranularity)),
			ByteCountBinary(int(time.Duration(highTickBytes)*time.Second/n.fuzzer.tickGranularity)))
		lowRoundCount, highRoundCount, lowRoundBytes, highRoundBytes := getRoundTrafficRanges(n.roundOutgoingTraffic)
		fmt.Printf("Outgoing Messages per round : [%d...%d]\n", lowRoundCount, highRoundCount)
		fmt.Printf("Outgoing Traffic per round : [%s...%s]\n", ByteCountBinary(lowRoundBytes), ByteCountBinary(highRoundBytes))

		fmt.Printf("Total Messages Received : %d\n", n.totalReceivedMessage.Count)
		fmt.Printf("Total Incoming Traffic : %s\n", ByteCountBinary(n.totalReceivedMessage.Bytes))
		lowTickCount, highTickCount, lowTickBytes, highTickBytes = getTickTrafficRanges(n.tickIncomingTraffic)
		fmt.Printf("Incoming Messages per tick : [%d...%d]\n", lowTickCount, highTickCount)
		fmt.Printf("Incoming Traffic : [%s/tick...%s/tick] [%s/sec...%s/sec]\n",
			ByteCountBinary(lowTickBytes),
			ByteCountBinary(highTickBytes),
			ByteCountBinary(int(time.Duration(lowTickBytes)*time.Second/n.fuzzer.tickGranularity)),
			ByteCountBinary(int(time.Duration(highTickBytes)*time.Second/n.fuzzer.tickGranularity)))
		lowRoundCount, highRoundCount, lowRoundBytes, highRoundBytes = getRoundTrafficRanges(n.roundIncomingTraffic)
		fmt.Printf("Incoming Messages per round : [%d...%d]\n", lowRoundCount, highRoundCount)
		fmt.Printf("Incoming Traffic per round : [%s...%s]\n", ByteCountBinary(lowRoundBytes), ByteCountBinary(highRoundBytes))

		fmt.Printf("Total Rounds : %d\n", n.lastNextRound-n.firstNextRound)

		fmt.Printf("\n")
	case 2:
		lowTickCount, highTickCount, lowTickBytes, highTickBytes := getTickTrafficRanges(n.tickOutgoingTraffic)
		lowRcvTickCount, highRcvTickCount, lowRcvTickBytes, highRcvTickBytes := getTickTrafficRanges(n.tickIncomingTraffic)
		fmt.Printf("%s%5d%11s%5d-%5d%11s-%10s%8d%11s%5d-%5d%11s-%10s",
			" ALL         ",
			n.totalSentMessage.Count,
			ByteCountBinary(n.totalSentMessage.Bytes),
			time.Duration(lowTickCount)*time.Second/n.fuzzer.tickGranularity,
			time.Duration(highTickCount)*time.Second/n.fuzzer.tickGranularity,
			ByteCountBinary(int(time.Duration(lowTickBytes)*time.Second/n.fuzzer.tickGranularity)),
			ByteCountBinary(int(time.Duration(highTickBytes)*time.Second/n.fuzzer.tickGranularity)),
			n.totalReceivedMessage.Count,
			ByteCountBinary(n.totalReceivedMessage.Bytes),
			time.Duration(lowRcvTickCount)*time.Second/n.fuzzer.tickGranularity,
			time.Duration(highRcvTickCount)*time.Second/n.fuzzer.tickGranularity,
			ByteCountBinary(int(time.Duration(lowRcvTickBytes)*time.Second/n.fuzzer.tickGranularity)),
			ByteCountBinary(int(time.Duration(highRcvTickBytes)*time.Second/n.fuzzer.tickGranularity)))
		fmt.Printf("\n")
	default:
	}
}

func (n *TrafficStatisticsFilterFactory) PreShutdown() {
	if n.printHeader {
		return
	}
	n.printHeader = true
	switch n.outputFormat {
	case 2:
		fmt.Printf("|Node|       |                  Outgoing                         |                      Incoming                              |\n")
		fmt.Printf("| ID | Round | Count |  Bytes  |  Msgs/sec  |    Bytes/sec       | Count |  Bytes  |  Msgs/sec  |    Bytes/sec    | Duplicate |\n")
	default:
	}
}

func (n *TrafficStatisticsFilterFactory) Gather() {
	if n.gatherOnce {
		return
	}
	n.gatherOnce = true
	for _, node := range n.nodes {
		n.totalSentMessage.IncreaseMetric(node.totalSentMessage.Count, node.totalSentMessage.Bytes)
		n.totalReceivedMessage.IncreaseMetric(node.totalReceivedMessage.Count, node.totalReceivedMessage.Bytes)
		if node.lastTick > n.lastTick {
			n.lastTick = node.lastTick
		}
		n.firstNextRound = node.firstNextRound
		if node.lastNextRound > n.lastNextRound {
			n.lastNextRound = node.lastNextRound
		}
		for tick, metrics := range node.tickOutgoingTraffic {
			if _, has := n.tickOutgoingTraffic[tick]; !has {
				n.tickOutgoingTraffic[tick] = &TrafficMetric{}
			}
			n.tickOutgoingTraffic[tick].IncreaseMetric(metrics.Count, metrics.Bytes)
		}
		for tick, metrics := range node.tickIncomingTraffic {
			if _, has := n.tickIncomingTraffic[tick]; !has {
				n.tickIncomingTraffic[tick] = &TrafficMetric{}
			}
			n.tickIncomingTraffic[tick].IncreaseMetric(metrics.Count, metrics.Bytes)
		}
		for round, metrics := range node.roundOutgoingTraffic {
			if _, has := n.roundOutgoingTraffic[round]; !has {
				n.roundOutgoingTraffic[round] = &TrafficMetric{}
			}
			n.roundOutgoingTraffic[round].IncreaseMetric(metrics.Count, metrics.Bytes)
		}
		for round, metrics := range node.roundIncomingTraffic {
			if _, has := n.roundIncomingTraffic[round]; !has {
				n.roundIncomingTraffic[round] = &TrafficMetric{}
			}
			n.roundIncomingTraffic[round].IncreaseMetric(metrics.Count, metrics.Bytes)
		}
		n.incomingDuplicateMessage.IncreaseMetric(node.incomingDuplicateMessage.Count, node.incomingDuplicateMessage.Bytes)
	}
	n.Print()
}
func MakeTrafficStatisticsFilterFactory(config *TrafficStatisticsFilterConfig) *TrafficStatisticsFilterFactory {
	return &TrafficStatisticsFilterFactory{
		nodes:                make(map[int]*TrafficStatisticsFilter),
		tickOutgoingTraffic:  make(map[int]*TrafficMetric),
		tickIncomingTraffic:  make(map[int]*TrafficMetric),
		roundOutgoingTraffic: make(map[basics.Round]*TrafficMetric),
		roundIncomingTraffic: make(map[basics.Round]*TrafficMetric),
		outputFormat:         config.OutputFormat,
	}
}

func (n *TrafficStatisticsFilterFactory) Unmarshal(b []byte) NetworkFilterFactory {
	type trafficFilterJSON struct {
		Name string
		TrafficStatisticsFilterConfig
	}
	var jsonConfig trafficFilterJSON
	if json.Unmarshal(b, &jsonConfig) != nil {
		return nil
	}
	if jsonConfig.Name != "TrafficStatisticsFilter" {
		return nil
	}
	return MakeTrafficStatisticsFilterFactory(&jsonConfig.TrafficStatisticsFilterConfig)
}

func init() {
	registeredFilterFactories = append(registeredFilterFactories, &TrafficStatisticsFilterFactory{})
}
