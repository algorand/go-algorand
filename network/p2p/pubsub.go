// Copyright (C) 2019-2024 Algorand, Inc.
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

	"github.com/algorand/go-algorand/config"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pubsub_pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/blake2b"
)

func init() {
	// configure larger overlay parameters
	pubsub.GossipSubD = 8
	pubsub.GossipSubDscore = 6
	pubsub.GossipSubDout = 3
	pubsub.GossipSubDlo = 6
	pubsub.GossipSubDhi = 12
	pubsub.GossipSubDlazy = 12
	pubsub.GossipSubDirectConnectInitialDelay = 30 * time.Second
	pubsub.GossipSubIWantFollowupTime = 5 * time.Second
	pubsub.GossipSubHistoryLength = 10
	pubsub.GossipSubGossipFactor = 0.1
}

const (
	gossipScoreThreshold             = -500
	publishScoreThreshold            = -1000
	graylistScoreThreshold           = -2500
	acceptPXScoreThreshold           = 1000
	opportunisticGraftScoreThreshold = 3.5
)

// TXTopicName defines a pubsub topic for TX messages
const TXTopicName = "/algo/tx/0.1.0"

func makePubSub(ctx context.Context, cfg config.Local, host host.Host) (*pubsub.PubSub, error) {
	//defaultParams := pubsub.DefaultGossipSubParams()

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
		// pubsub.WithValidateThrottle(cfg.TxBacklogSize),
	}

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
func (s *serviceImpl) Subscribe(topic string, val pubsub.ValidatorEx) (*pubsub.Subscription, error) {
	if err := s.pubsub.RegisterTopicValidator(topic, val); err != nil {
		return nil, err
	}
	t, err := s.getOrCreateTopic(topic)
	if err != nil {
		return nil, err
	}
	// t.SetScoreParams() // already set in makePubSub
	return t.Subscribe()
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
