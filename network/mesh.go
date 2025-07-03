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

package network

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/p2p/discovery/backoff"
)

const meshThreadInterval = time.Minute

type meshStrategy interface {
	meshThread()
	start()
	stop()
}

type genericMeshStrategy struct {
	ctx                context.Context
	meshUpdateRequests chan meshRequest
	meshThreadInterval time.Duration
	wg                 sync.WaitGroup
	meshConfig
}

type meshConfig struct {
	backoff        backoff.BackoffStrategy
	netMesh        func() bool
	netDisconnect  func()
	peerStatReport func()
	closer         func()
}

type hybridRelayMeshStrategy struct {
	genericMeshStrategy
}

type meshStrategyOption func(*meshConfig)

func withMeshExpJitterBackoff() meshStrategyOption {
	return func(cfg *meshConfig) {
		// Add exponential backoff with jitter to the mesh thread to handle new networks startup
		// when no DNS or DHT peers are available.
		// The parameters produce approximate the following delays (although they are random but the sequence give the idea):
		// 2 2.4 4.6 9 20 19.5 28 24 14 14 35 60 60
		ebf := backoff.NewExponentialDecorrelatedJitter(2*time.Second, meshThreadInterval, 3.0, rand.NewSource(rand.Int63()))
		eb := ebf()
		cfg.backoff = eb
	}
}
func withMeshNetMesh(netMesh func() bool) meshStrategyOption {
	return func(cfg *meshConfig) {
		cfg.netMesh = netMesh
	}
}
func withMeshNetDisconnect(netDisconnect func()) meshStrategyOption {
	return func(cfg *meshConfig) {
		cfg.netDisconnect = netDisconnect
	}
}
func withMeshPeerStatReport(peerStatReport func()) meshStrategyOption {
	return func(cfg *meshConfig) {
		cfg.peerStatReport = peerStatReport
	}
}
func withMeshCloser(closer func()) meshStrategyOption {
	return func(cfg *meshConfig) {
		cfg.closer = closer
	}
}

func newGenericMeshStrategy(ctx context.Context, meshUpdateRequests chan meshRequest, meshThreadInterval time.Duration, opts ...meshStrategyOption) (*genericMeshStrategy, error) {
	var cfg meshConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.netMesh == nil {
		return nil, errors.New("mesh function is not set")
	}
	if cfg.netDisconnect == nil {
		return nil, errors.New("disconnect function is not set")
	}

	return &genericMeshStrategy{
		ctx:                ctx,
		meshUpdateRequests: meshUpdateRequests,
		meshThreadInterval: meshThreadInterval,
		meshConfig:         cfg,
	}, nil
}

func (m *genericMeshStrategy) meshThread() {
	defer m.wg.Done()

	timer := time.NewTicker(m.meshThreadInterval)
	defer timer.Stop()
	for {
		var request meshRequest
		select {
		case <-timer.C:
			request.disconnect = false
			request.done = nil
		case request = <-m.meshUpdateRequests:
		case <-m.ctx.Done():
			return
		}

		if request.disconnect {
			m.netDisconnect()
		}

		hasPeers := m.netMesh()
		if m.backoff != nil {
			if hasPeers {
				// found something, reset timer to the default value
				timer.Reset(meshThreadInterval)
				m.backoff.Reset()
			} else {
				// no peers found, backoff
				timer.Reset(m.backoff.Delay())
			}
		}
		if request.done != nil {
			close(request.done)
		}

		// send the currently connected peers information to the
		// telemetry server; that would allow the telemetry server
		// to construct a cross-node map of all the nodes interconnections.
		m.peerStatReport()
	}
}

func (m *genericMeshStrategy) start() {
	m.wg.Add(1)
	go m.meshThread()
}

func (m *genericMeshStrategy) stop() {
	m.wg.Wait()
}

// MeshStrategyCreator is an interface for creating mesh strategies.
type MeshStrategyCreator interface {
	create(ctx context.Context, meshUpdateRequests chan meshRequest, meshThreadInterval time.Duration, opts ...meshStrategyOption) (meshStrategy, error)
}

// GenericMeshStrategyCreator is a creator for the generic mesh strategy used in our standard WS or P2P implementations:
// run a mesh thread that periodically checks for new peers.
type GenericMeshStrategyCreator struct {
}

func (c *GenericMeshStrategyCreator) create(ctx context.Context, meshUpdateRequests chan meshRequest, meshThreadInterval time.Duration, opts ...meshStrategyOption) (meshStrategy, error) {
	return newGenericMeshStrategy(ctx, meshUpdateRequests, meshThreadInterval, opts...)
}

// HybridRelayMeshStrategyCreator is a creator for the hybrid relay mesh strategy used in hybrid relays:
// first attempt to connect to relays using WS net, and if not enough peers then continue with P2P net.
type HybridRelayMeshStrategyCreator struct {
	p2pMeshOptions        meshConfig
	p2pMeshUpdateRequests chan meshRequest

	out chan meshRequest
	wg  sync.WaitGroup
}

func (c *HybridRelayMeshStrategyCreator) create(ctx context.Context, meshUpdateRequests chan meshRequest, meshThreadInterval time.Duration, opts ...meshStrategyOption) (meshStrategy, error) {
	c.out = make(chan meshRequest, 5)
	opts = append(opts, withMeshCloser(func() {
		// wait for meshUpdateRequests fan-in goroutines to finish and close the output channel
		c.wg.Wait()
		close(c.out)
	}))
	strategy, err := newHybridRelayMeshStrategy(ctx, c.out, meshThreadInterval, opts...)
	if err != nil {
		return nil, err
	}
	wsNetDisconnect := strategy.netDisconnect
	strategy.netDisconnect = func() {
		wsNetDisconnect()
		c.p2pMeshOptions.netDisconnect()
	}
	wsNetPeerStatReport := strategy.peerStatReport
	strategy.peerStatReport = func() {
		wsNetPeerStatReport()
		c.p2pMeshOptions.peerStatReport()
	}

	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		select {
		case <-ctx.Done():
			return
		case req := <-meshUpdateRequests:
			c.out <- req
		}
	}()

	go func() {
		defer c.wg.Done()
		select {
		case <-ctx.Done():
			return
		case req := <-c.p2pMeshUpdateRequests:
			c.out <- req
		}
	}()

	return strategy, nil
}

func newHybridRelayMeshStrategy(ctx context.Context, meshUpdateRequests chan meshRequest, meshThreadInterval time.Duration, opts ...meshStrategyOption) (*hybridRelayMeshStrategy, error) {
	var cfg meshConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.netMesh == nil {
		return nil, errors.New("mesh function is not set")
	}
	if cfg.netDisconnect == nil {
		return nil, errors.New("disconnect function is not set")
	}

	return &hybridRelayMeshStrategy{
		genericMeshStrategy: genericMeshStrategy{
			ctx:                ctx,
			meshUpdateRequests: meshUpdateRequests,
			meshThreadInterval: meshThreadInterval,
			meshConfig:         cfg,
		},
	}, nil
}

func (m *hybridRelayMeshStrategy) meshThread() {
	m.genericMeshStrategy.meshThread()
}

func (m *hybridRelayMeshStrategy) start() {
	m.wg.Add(1)
	go m.meshThread()
}

func (m *hybridRelayMeshStrategy) stop() {
	m.wg.Wait()
	if m.closer != nil {
		m.closer()
	}
}

type dummyMeshCreator struct {
	mc                 meshConfig
	meshUpdateRequests chan meshRequest
}

func (c *dummyMeshCreator) create(ctx context.Context, meshUpdateRequests chan meshRequest, meshThreadInterval time.Duration, opts ...meshStrategyOption) (meshStrategy, error) {
	var cfg meshConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.netMesh == nil {
		return nil, errors.New("mesh function is not set")
	}
	if cfg.netDisconnect == nil {
		return nil, errors.New("disconnect function is not set")
	}
	c.mc = cfg
	c.meshUpdateRequests = meshUpdateRequests
	return &noopMeshStrategy{}, nil
}

type noopMeshStrategy struct{}

func (m *noopMeshStrategy) meshThread() {
}
func (m *noopMeshStrategy) start() {
}
func (m *noopMeshStrategy) stop() {
}
