// Copyright (C) 2019-2026 Algorand, Inc.
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

package p2p

import (
	"context"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pubsub_pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/blake2b"

	pstore "github.com/algorand/go-algorand/network/p2p/peerstore"
)

// PubSubOption is a function that modifies the pubsub options
type PubSubOption func(opts *[]pubsub.Option, params *pubsub.GossipSubParams)

// DisablePubSubPeerExchange disables PX (peer exchange) in pubsub
func DisablePubSubPeerExchange() PubSubOption {
	return func(opts *[]pubsub.Option, _ *pubsub.GossipSubParams) {
		*opts = append(*opts, pubsub.WithPeerExchange(false))
	}
}

// SetPubSubMetricsTracer sets a pubsub.RawTracer for metrics collection
func SetPubSubMetricsTracer(metricsTracer pubsub.RawTracer) PubSubOption {
	return func(opts *[]pubsub.Option, _ *pubsub.GossipSubParams) {
		*opts = append(*opts, pubsub.WithRawTracer(metricsTracer))
	}
}

// SetPubSubPeerFilter sets a pubsub.PeerFilter for peers filtering out
func SetPubSubPeerFilter(filter func(checker pstore.RoleChecker, pid peer.ID) bool, checker pstore.RoleChecker) PubSubOption {
	return func(opts *[]pubsub.Option, _ *pubsub.GossipSubParams) {
		f := func(pid peer.ID, topic string) bool {
			return filter(checker, pid)
		}
		*opts = append(*opts, pubsub.WithPeerFilter(f))
	}
}

// SetPubSubHeartbeatInterval sets the heartbeat interval in pubsub GossipSubParams
// Note: subsequent call of pubsub.WithGossipSubParams is needed.
func SetPubSubHeartbeatInterval(interval time.Duration) PubSubOption {
	return func(opts *[]pubsub.Option, params *pubsub.GossipSubParams) {
		params.HeartbeatInterval = interval
	}
}

const (
	gossipScoreThreshold             = -500
	publishScoreThreshold            = -1000
	graylistScoreThreshold           = -2500
	acceptPXScoreThreshold           = 1000
	opportunisticGraftScoreThreshold = 3.5
)

// TXTopicName defines a pubsub topic for TX messages
// There is a micro optimization for const string comparison:
// 8 bytes const string require a single x86-64 CMPQ instruction.
// Naming convention: "algo" + 2 bytes protocol tag + 2 bytes version
const TXTopicName = "algotx01"

const incomingThreads = 20 // matches to number wsNetwork workers

// deriveAlgorandGossipSubParams derives the gossip sub parameters from the cfg.GossipFanout value
// by using the same proportions as pubsub defaults - see GossipSubD, GossipSubDlo, etc.
func deriveAlgorandGossipSubParams(numOutgoingConns int) pubsub.GossipSubParams {
	params := pubsub.DefaultGossipSubParams()

	// configure larger overlay parameters
	params.D = 8
	params.Dscore = 6
	params.Dout = 3
	params.Dlo = 6
	params.Dhi = 12
	params.Dlazy = 12
	params.DirectConnectInitialDelay = 30 * time.Second
	params.IWantFollowupTime = 5 * time.Second
	params.HistoryLength = 10
	params.GossipFactor = 0.1

	params.D = numOutgoingConns
	params.Dlo = params.D - 1
	if params.Dlo <= 0 {
		params.Dlo = params.D
	}
	params.Dscore = params.D * 2 / 3
	params.Dout = params.D * 1 / 3
	return params
}

func makePubSub(ctx context.Context, host host.Host, numOutgoingConns int, pubsubOptions ...PubSubOption) (*pubsub.PubSub, error) {
	options := []pubsub.Option{
		pubsub.WithPeerScore(&pubsub.PeerScoreParams{
			DecayInterval: pubsub.DefaultDecayInterval,
			DecayToZero:   pubsub.DefaultDecayToZero,

			AppSpecificScore: func(p peer.ID) float64 { return 1000 },

			Topics: map[string]*pubsub.TopicScoreParams{
				TXTopicName: {
					TopicWeight: 0.1,

					TimeInMeshWeight:  0.0002778, // ~1/3600
					TimeInMeshQuantum: time.Second,
					TimeInMeshCap:     1,

					FirstMessageDeliveriesWeight: 0.5, // max value is 50
					FirstMessageDeliveriesDecay:  pubsub.ScoreParameterDecay(10 * time.Minute),
					FirstMessageDeliveriesCap:    100, // 100 messages in 10 minutes

					// invalid messages decay after 1 hour
					InvalidMessageDeliveriesWeight: -1000,
					InvalidMessageDeliveriesDecay:  pubsub.ScoreParameterDecay(time.Hour),
				},
			},
		},
			&pubsub.PeerScoreThresholds{
				GossipThreshold:             gossipScoreThreshold,
				PublishThreshold:            publishScoreThreshold,
				GraylistThreshold:           graylistScoreThreshold,
				AcceptPXThreshold:           acceptPXScoreThreshold,
				OpportunisticGraftThreshold: opportunisticGraftScoreThreshold,
			},
		),
		// pubsub.WithPeerGater(&pubsub.PeerGaterParams{}),
		pubsub.WithSubscriptionFilter(pubsub.WrapLimitSubscriptionFilter(pubsub.NewAllowlistSubscriptionFilter(TXTopicName), 100)),
		// pubsub.WithEventTracer(jsonTracer),
		pubsub.WithValidateQueueSize(256),
		pubsub.WithMessageSignaturePolicy(pubsub.StrictNoSign),
		// pubsub.WithValidateThrottle(cfg.TxBacklogSize),
		pubsub.WithValidateWorkers(incomingThreads),
	}

	gossipSubParams := deriveAlgorandGossipSubParams(numOutgoingConns)
	for _, opt := range pubsubOptions {
		opt(&options, &gossipSubParams)
	}
	options = append(options, pubsub.WithGossipSubParams(gossipSubParams))

	return pubsub.NewGossipSub(ctx, host, options...)
}

func txMsgID(m *pubsub_pb.Message) string {
	h := blake2b.Sum256(m.Data)
	return string(h[:])
}

// getOrCreateTopic returns a topic if it was already joined previously and otherwise creates it and adds it to the topics map
func (s *serviceImpl) getOrCreateTopic(topicName string) (*pubsub.Topic, error) {
	s.topicsMu.RLock()
	topic, ok := s.topics[topicName]
	s.topicsMu.RUnlock()
	if ok {
		return topic, nil
	}

	s.topicsMu.Lock()
	defer s.topicsMu.Unlock()
	// check again in case it was created while we were waiting for the lock
	if _, ok := s.topics[topicName]; !ok {
		var topt []pubsub.TopicOpt
		switch topicName {
		case TXTopicName:
			topt = append(topt, pubsub.WithTopicMessageIdFn(txMsgID))
		}

		psTopic, err := s.pubsub.Join(topicName, topt...)
		if err != nil {
			return nil, err
		}
		s.topics[topicName] = psTopic
	}
	return s.topics[topicName], nil
}

// Subscribe returns a subscription to the given topic
func (s *serviceImpl) Subscribe(topic string, val pubsub.ValidatorEx) (SubNextCancellable, error) {
	if err := s.pubsub.RegisterTopicValidator(topic, val); err != nil {
		return nil, err
	}
	t, err := s.getOrCreateTopic(topic)
	if err != nil {
		return nil, err
	}
	// t.SetScoreParams() // already set in makePubSub
	return t.Subscribe(pubsub.WithBufferSize(32768))
}

// Publish publishes data to the given topic
func (s *serviceImpl) Publish(ctx context.Context, topic string, data []byte) error {
	t, err := s.getOrCreateTopic(topic)
	if err != nil {
		return err
	}
	return t.Publish(ctx, data)
}

// ListPeersForTopic returns a list of peers subscribed to the given topic, exported for access from the network package
func (s *serviceImpl) ListPeersForTopic(topic string) []peer.ID {
	return s.pubsub.ListPeers(topic)
}
