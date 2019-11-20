// Copyright (C) 2019 Algorand, Inc.
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

package logging

import (
	"fmt"

	"github.com/olivere/elastic"
	"github.com/sirupsen/logrus"
	"gopkg.in/sohlich/elogrus.v3"

	"github.com/algorand/go-algorand/util/metrics"
)

var telemetryDrops = metrics.MakeCounter(metrics.MetricName{Name: "algod_telemetry_drops_total", Description: "telemetry messages not sent to server"})

func createAsyncHook(wrappedHook logrus.Hook, channelDepth uint, maxQueueDepth int) *asyncTelemetryHook {
	return createAsyncHookLevels(wrappedHook, channelDepth, maxQueueDepth, makeLevels(logrus.InfoLevel))
}

func createAsyncHookLevels(wrappedHook logrus.Hook, channelDepth uint, maxQueueDepth int, levels []logrus.Level) *asyncTelemetryHook {
	// one time check to see if the wrappedHook is ready (true for mocked telemetry)
	tfh, ok := wrappedHook.(*telemetryFilteredHook)
	ready := ok && tfh.wrappedHook != nil

	hook := &asyncTelemetryHook{
		wrappedHook:   wrappedHook,
		entries:       make(chan *logrus.Entry, channelDepth),
		quit:          make(chan struct{}),
		maxQueueDepth: maxQueueDepth,
		levels:        levels,
		ready:         ready,
		urlUpdate:     make(chan bool),
	}

	go func() {
		defer hook.wg.Done()

		exit := false
		for !exit {
			exit = !hook.waitForEventAndReady()

			hasEvents := true

			for hasEvents {
				select {
				case entry := <-hook.entries:
					hook.appendEntry(entry)
				default:
					hook.Lock()
					var entry *logrus.Entry
					if len(hook.pending) > 0 && hook.ready {
						entry = hook.pending[0]
						hook.pending = hook.pending[1:]
					}
					hook.Unlock()
					if entry != nil {
						hook.wrappedHook.Fire(entry)
						hook.wg.Done()
					} else {
						hasEvents = false
					}
				}
			}
		}
	}()

	return hook
}

func (hook *asyncTelemetryHook) appendEntry(entry *logrus.Entry) bool {
	hook.Lock()
	defer hook.Unlock()
	// TODO: If there are errors at startup, before the telemetry URI is set, this can fill up. Should we prioritize
	//       startup / heartbeat events?
	if len(hook.pending) >= hook.maxQueueDepth {
		hook.pending = hook.pending[1:]
		hook.wg.Done()
	}
	hook.pending = append(hook.pending, entry)

	// Return ready here to avoid taking the lock again.
	return hook.ready
}

func (hook *asyncTelemetryHook) waitForEventAndReady() bool {
	for {
		select {
		case <-hook.quit:
			return false
		case entry := <-hook.entries:
			ready := hook.appendEntry(entry)

			// Otherwise keep waiting for the URL to update.
			if ready {
				return true
			}
		case <-hook.urlUpdate:
			hook.Lock()
			hasEvents := len(hook.pending) > 0
			hook.Unlock()

			// Otherwise keep waiting for an entry.
			if hasEvents {
				return true
			}
		}
	}
}

// Fire is required to implement logrus hook interface
func (hook *asyncTelemetryHook) Fire(entry *logrus.Entry) error {
	hook.wg.Add(1)
	select {
	case hook.entries <- entry:
	default:
		hook.wg.Done()
		// queue is full, don't block, drop message.

		// metrics is a different mechanism that will never block
		telemetryDrops.Inc(nil)
	}
	return nil
}

// Levels Required for logrus hook interface
func (hook *asyncTelemetryHook) Levels() []logrus.Level {
	if hook.wrappedHook != nil {
		return hook.wrappedHook.Levels()
	}

	return hook.levels
}

func (hook *asyncTelemetryHook) Close() {
	hook.wg.Add(1)
	close(hook.quit)
	hook.wg.Wait()
}

func (hook *asyncTelemetryHook) Flush() {
	hook.wg.Wait()
}

func createElasticHook(cfg TelemetryConfig) (hook logrus.Hook, err error) {
	// Returning an error here causes issues... need the hooks to be created even if the elastic hook fails so that
	// things can recover later.
	if cfg.URI == "" {
		return nil, nil
	}

	client, err := elastic.NewClient(elastic.SetURL(cfg.URI),
		elastic.SetBasicAuth(cfg.UserName, cfg.Password),
		elastic.SetSniff(false),
		elastic.SetGzip(true))
	if err != nil {
		return nil, err
	}
	hostName := cfg.getHostName()
	hook, err = elogrus.NewElasticHook(client, hostName, cfg.MinLogLevel, cfg.ChainID)

	return hook, err
}

// createTelemetryHook creates the Telemetry log hook, or returns nil if remote logging is not enabled
func createTelemetryHook(cfg TelemetryConfig, history *logBuffer, hookFactory hookFactory) (hook logrus.Hook, err error) {
	if !cfg.Enable {
		return nil, fmt.Errorf("createTelemetryHook called when telemetry not enabled")
	}

	hook, err = hookFactory(cfg)

	if err != nil {
		return nil, err
	}

	filteredHook, err := newTelemetryFilteredHook(cfg, hook, cfg.ReportHistoryLevel, history, cfg.SessionGUID, hookFactory, makeLevels(cfg.MinLogLevel))

	return filteredHook, err
}

// Note: This will be removed with the externalized telemetry project. Return whether or not the URI was successfully
//       updated.
func (hook *asyncTelemetryHook) UpdateHookURI(uri string) bool {
	updated := false

	if hook.wrappedHook == nil {
		return false
	}

	tfh, ok := hook.wrappedHook.(*telemetryFilteredHook)
	if ok {
		hook.Lock()

		copy := tfh.telemetryConfig
		copy.URI = uri
		newHook, err := tfh.factory(copy)

		if err == nil && newHook != nil {
			tfh.wrappedHook = newHook
			tfh.telemetryConfig.URI = uri
			hook.ready = true
			updated = true
		}

		// Need to unlock before sending event to hook.urlUpdate
		hook.Unlock()

		// Notify event listener if the hook was created.
		if updated {
			hook.urlUpdate <- true
		}
	}
	return updated
}
