// Copyright (C) 2019-2020 Algorand, Inc.
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
		defer func() {
			// flush the channel
			moreEntries := true
			for moreEntries {
				select {
				case entry := <-hook.entries:
					hook.appendEntry(entry)
				default:
					moreEntries = false
				}
			}
			for range hook.pending {
				// The telemetry service is
				// exiting. Un-wait for the left out
				// messages.
				hook.wg.Done()
			}
			hook.wg.Done()
		}()

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
						err := hook.wrappedHook.Fire(entry)
						if err != nil {
							Base().Warnf("Unable to write event %#v to telemetry : %v", entry, err)
						}
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

// appendEntry adds the given entry to the pending slice and returns whether the hook is ready or not.
func (hook *asyncTelemetryHook) appendEntry(entry *logrus.Entry) bool {
	hook.Lock()
	defer hook.Unlock()
	// TODO: If there are errors at startup, before the telemetry URI is set, this can fill up. Should we prioritize
	//       startup / heartbeat events?
	if len(hook.pending) >= hook.maxQueueDepth {
		hook.pending = hook.pending[1:]
		hook.wg.Done()
		telemetryDrops.Inc(nil)
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
	case <-hook.quit:
		// telemetry quit
		hook.wg.Done()
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

func (hook *dummyHook) UpdateHookURI(uri string) (err error) {
	return
}
func (hook *dummyHook) Levels() []logrus.Level {
	return []logrus.Level{}
}
func (hook *dummyHook) Fire(entry *logrus.Entry) error {
	return nil
}
func (hook *dummyHook) Close() {
}
func (hook *dummyHook) Flush() {
}

func (hook *dummyHook) appendEntry(entry *logrus.Entry) bool {
	return true
}
func (hook *dummyHook) waitForEventAndReady() bool {
	return true
}

// the elasticClientLogger is used to bridge the elastic library error reporting
// into our own logging system.
type elasticClientLogger struct {
	logger Logger       // points to the underlying logger which would perform the logging
	level  logrus.Level // indicate what logging level we want to use for the logging
}

// Printf tunnel the log string into the log file.
func (el elasticClientLogger) Printf(format string, v ...interface{}) {
	switch el.level {
	case logrus.DebugLevel:
		el.logger.Debugf(format, v...)
	case logrus.InfoLevel:
		el.logger.Infof(format, v...)
	case logrus.WarnLevel:
		el.logger.Warnf(format, v...)
	default:
		el.logger.Errorf(format, v...)
	}
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
		elastic.SetGzip(true),
		elastic.SetTraceLog(&elasticClientLogger{logger: Base(), level: logrus.DebugLevel}),
		elastic.SetInfoLog(&elasticClientLogger{logger: Base(), level: logrus.DebugLevel}),
		elastic.SetErrorLog(&elasticClientLogger{logger: Base(), level: logrus.WarnLevel}),
	)
	if err != nil {
		err = fmt.Errorf("Unable to create new elastic client on '%s' using '%s:%s' : %w", cfg.URI, cfg.UserName, cfg.Password, err)
		return nil, err
	}
	hostName := cfg.getHostName()
	hook, err = elogrus.NewElasticHook(client, hostName, cfg.MinLogLevel, cfg.ChainID)

	if err != nil {
		err = fmt.Errorf("Unable to create new elastic hook on host '%s' using chainID '%s' : %w", hostName, cfg.ChainID, err)
	}
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
func (hook *asyncTelemetryHook) UpdateHookURI(uri string) (err error) {
	updated := false

	if hook.wrappedHook == nil {
		return fmt.Errorf("asyncTelemetryHook.wrappedHook is nil")
	}

	tfh, ok := hook.wrappedHook.(*telemetryFilteredHook)
	if ok {
		hook.Lock()

		copy := tfh.telemetryConfig
		copy.URI = uri
		var newHook logrus.Hook
		newHook, err = tfh.factory(copy)

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
	} else {
		return fmt.Errorf("asyncTelemetryHook.wrappedHook does not implement telemetryFilteredHook")
	}
	return
}
