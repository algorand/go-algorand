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

package config

import (
	"fmt"
	"time"
)

var defaultLocal = defaultLocalV6

const configVersion = uint32(6)

// !!! WARNING !!!
//
// These versioned structures need to be maintained CAREFULLY and treated
// like UNIVERSAL CONSTANTS - they should not be modified once committed.
//
// New fields may be added to the current defaultLocalV# and should
// also be added to installer/config.json.example and
// test/testdata/configs/config-v{n}.json
//
// Changing a default value requires creating a new defaultLocalV# instance,
// bump the version number (configVersion), and add appropriate migration and tests.
//
// !!! WARNING !!!

var defaultLocalV6 = Local{
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
	Version:                               6,
	Archival:                              false,
	BaseLoggerDebugLevel:                  4,
	BroadcastConnectionsLimit:             -1,
	AnnounceParticipationKey:              true,
	PriorityPeers:                         map[string]bool{},
	CadaverSizeTarget:                     1073741824,
	CatchupFailurePeerRefreshRate:         10,
	CatchupParallelBlocks:                 16,
	ConnectionsRateLimitingCount:          60,
	ConnectionsRateLimitingWindowSeconds:  1,
	DeadlockDetection:                     0,
	DNSBootstrapID:                        "<network>.algorand.network",
	EnableAgreementReporting:              false,
	EnableAgreementTimeMetrics:            false,
	EnableIncomingMessageFilter:           false,
	EnableMetricReporting:                 false,
	EnableOutgoingNetworkMessageFiltering: true,
	EnableRequestLogger:                   false,
	EnableTopAccountsReporting:            false,
	EndpointAddress:                       "127.0.0.1:0",
	GossipFanout:                          4,
	IncomingConnectionsLimit:              10000,
	IncomingMessageFilterBucketCount:      5,
	IncomingMessageFilterBucketSize:       512,
	LogArchiveName:                        "node.archive.log",
	LogArchiveMaxAge:                      "",
	LogSizeLimit:                          1073741824,
	MaxConnectionsPerIP:                   30,
	NetAddress:                            "",
	NodeExporterListenAddress:             ":9100",
	NodeExporterPath:                      "./node_exporter",
	OutgoingMessageFilterBucketCount:      3,
	OutgoingMessageFilterBucketSize:       128,
	ReconnectTime:                         1 * time.Minute,
	ReservedFDs:                           256,
	RestReadTimeoutSeconds:                15,
	RestWriteTimeoutSeconds:               120,
	RunHosted:                             false,
	SuggestedFeeBlockHistory:              3,
	SuggestedFeeSlidingWindowSize:         50,
	TelemetryToLog:                        true,
	TxPoolExponentialIncreaseFactor:       2,
	TxPoolSize:                            15000,
	TxSyncIntervalSeconds:                 60,
	TxSyncTimeoutSeconds:                  30,
	TxSyncServeResponseSize:               1000000,
	PeerConnectionsUpdateInterval:         3600,
	DNSSecurityFlags:                      0x01, // New value with default 0x01
	EnablePingHandler:                     true,
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
}

var defaultLocalV5 = Local{
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
	Version:                               5,
	Archival:                              false,
	BaseLoggerDebugLevel:                  4, // Was 1
	BroadcastConnectionsLimit:             -1,
	AnnounceParticipationKey:              true,
	PriorityPeers:                         map[string]bool{},
	CadaverSizeTarget:                     1073741824,
	CatchupFailurePeerRefreshRate:         10,
	CatchupParallelBlocks:                 16,
	ConnectionsRateLimitingCount:          60,
	ConnectionsRateLimitingWindowSeconds:  1,
	DeadlockDetection:                     0,
	DNSBootstrapID:                        "<network>.algorand.network",
	EnableAgreementReporting:              false,
	EnableAgreementTimeMetrics:            false,
	EnableIncomingMessageFilter:           false,
	EnableMetricReporting:                 false,
	EnableOutgoingNetworkMessageFiltering: true,
	EnableRequestLogger:                   false,
	EnableTopAccountsReporting:            false,
	EndpointAddress:                       "127.0.0.1:0",
	GossipFanout:                          4,
	IncomingConnectionsLimit:              10000, // Was -1
	IncomingMessageFilterBucketCount:      5,
	IncomingMessageFilterBucketSize:       512,
	LogArchiveName:                        "node.archive.log",
	LogArchiveMaxAge:                      "",
	LogSizeLimit:                          1073741824,
	MaxConnectionsPerIP:                   30,
	NetAddress:                            "",
	NodeExporterListenAddress:             ":9100",
	NodeExporterPath:                      "./node_exporter",
	OutgoingMessageFilterBucketCount:      3,
	OutgoingMessageFilterBucketSize:       128,
	ReconnectTime:                         1 * time.Minute, // Was 60ns
	ReservedFDs:                           256,
	RestReadTimeoutSeconds:                15,
	RestWriteTimeoutSeconds:               120,
	RunHosted:                             false,
	SuggestedFeeBlockHistory:              3,
	SuggestedFeeSlidingWindowSize:         50,
	TelemetryToLog:                        true,
	TxPoolExponentialIncreaseFactor:       2,
	TxPoolSize:                            15000,
	TxSyncIntervalSeconds:                 60,
	TxSyncTimeoutSeconds:                  30,
	TxSyncServeResponseSize:               1000000,
	PeerConnectionsUpdateInterval:         3600,
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
}

var defaultLocalV4 = Local{
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
	Version:                               4,
	Archival:                              false,
	BaseLoggerDebugLevel:                  4, // Was 1
	BroadcastConnectionsLimit:             -1,
	AnnounceParticipationKey:              true,
	PriorityPeers:                         map[string]bool{},
	CadaverSizeTarget:                     1073741824,
	CatchupFailurePeerRefreshRate:         10,
	CatchupParallelBlocks:                 50,
	ConnectionsRateLimitingCount:          60,
	ConnectionsRateLimitingWindowSeconds:  1,
	DeadlockDetection:                     0,
	DNSBootstrapID:                        "<network>.algorand.network",
	EnableAgreementReporting:              false,
	EnableAgreementTimeMetrics:            false,
	EnableIncomingMessageFilter:           false,
	EnableMetricReporting:                 false,
	EnableOutgoingNetworkMessageFiltering: true,
	EnableRequestLogger:                   false,
	EnableTopAccountsReporting:            false,
	EndpointAddress:                       "127.0.0.1:0",
	GossipFanout:                          4,
	IncomingConnectionsLimit:              10000, // Was -1
	IncomingMessageFilterBucketCount:      5,
	IncomingMessageFilterBucketSize:       512,
	LogArchiveName:                        "node.archive.log",
	LogArchiveMaxAge:                      "",
	LogSizeLimit:                          1073741824,
	MaxConnectionsPerIP:                   30,
	NetAddress:                            "",
	NodeExporterListenAddress:             ":9100",
	NodeExporterPath:                      "./node_exporter",
	OutgoingMessageFilterBucketCount:      3,
	OutgoingMessageFilterBucketSize:       128,
	ReconnectTime:                         1 * time.Minute, // Was 60ns
	ReservedFDs:                           256,
	RestReadTimeoutSeconds:                15,
	RestWriteTimeoutSeconds:               120,
	RunHosted:                             false,
	SuggestedFeeBlockHistory:              3,
	SuggestedFeeSlidingWindowSize:         50,
	TxPoolExponentialIncreaseFactor:       2,
	TxPoolSize:                            50000,
	TxSyncIntervalSeconds:                 60,
	TxSyncTimeoutSeconds:                  30,
	TxSyncServeResponseSize:               1000000,

	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
}

var defaultLocalV3 = Local{
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
	Version:                               3,
	Archival:                              false,
	BaseLoggerDebugLevel:                  4, // Was 1
	CadaverSizeTarget:                     1073741824,
	CatchupFailurePeerRefreshRate:         10,
	CatchupParallelBlocks:                 50,
	DeadlockDetection:                     0,
	DNSBootstrapID:                        "<network>.algorand.network",
	EnableAgreementReporting:              false,
	EnableAgreementTimeMetrics:            false,
	EnableIncomingMessageFilter:           false,
	EnableMetricReporting:                 false,
	EnableOutgoingNetworkMessageFiltering: true,
	EnableTopAccountsReporting:            false,
	EndpointAddress:                       "127.0.0.1:0",
	GossipFanout:                          4,
	IncomingConnectionsLimit:              10000, // Was -1
	IncomingMessageFilterBucketCount:      5,
	IncomingMessageFilterBucketSize:       512,
	LogSizeLimit:                          1073741824,
	MaxConnectionsPerIP:                   30,
	NetAddress:                            "",
	NodeExporterListenAddress:             ":9100",
	NodeExporterPath:                      "./node_exporter",
	OutgoingMessageFilterBucketCount:      3,
	OutgoingMessageFilterBucketSize:       128,
	ReconnectTime:                         1 * time.Minute, // Was 60ns
	ReservedFDs:                           256,
	RunHosted:                             false,
	SuggestedFeeBlockHistory:              3,
	SuggestedFeeSlidingWindowSize:         50,
	TxPoolExponentialIncreaseFactor:       2,
	TxPoolSize:                            50000,
	TxSyncIntervalSeconds:                 60,
	TxSyncTimeoutSeconds:                  30,
	TxSyncServeResponseSize:               1000000,
	IsIndexerActive:                       false,
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
}

var defaultLocalV2 = Local{
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
	Version:                               2,
	Archival:                              false,
	BaseLoggerDebugLevel:                  4, // Was 1
	CadaverSizeTarget:                     1073741824,
	CatchupFailurePeerRefreshRate:         10,
	DeadlockDetection:                     0,
	DNSBootstrapID:                        "<network>.algorand.network",
	EnableIncomingMessageFilter:           false,
	EnableMetricReporting:                 false,
	EnableOutgoingNetworkMessageFiltering: true,
	EnableTopAccountsReporting:            false,
	EndpointAddress:                       "127.0.0.1:0",
	GossipFanout:                          4,
	IncomingConnectionsLimit:              10000, // Was -1
	IncomingMessageFilterBucketCount:      5,
	IncomingMessageFilterBucketSize:       512,
	LogSizeLimit:                          1073741824,
	NetAddress:                            "",
	NodeExporterListenAddress:             ":9100",
	NodeExporterPath:                      "./node_exporter",
	OutgoingMessageFilterBucketCount:      3,
	OutgoingMessageFilterBucketSize:       128,
	ReconnectTime:                         1 * time.Minute, // Was 60ns
	ReservedFDs:                           256,
	SuggestedFeeBlockHistory:              3,
	TxPoolExponentialIncreaseFactor:       2,
	TxPoolSize:                            50000,
	TxSyncIntervalSeconds:                 60,
	TxSyncTimeoutSeconds:                  30,
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
}

var defaultLocalV1 = Local{
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
	Version:                               1,
	Archival:                              false,
	BaseLoggerDebugLevel:                  4, // Was 1
	CadaverSizeTarget:                     1073741824,
	CatchupFailurePeerRefreshRate:         10,
	DeadlockDetection:                     0,
	DNSBootstrapID:                        "<network>.algorand.network",
	EnableIncomingMessageFilter:           false,
	EnableMetricReporting:                 false,
	EnableOutgoingNetworkMessageFiltering: true,
	EnableTopAccountsReporting:            false,
	EndpointAddress:                       "127.0.0.1:0",
	GossipFanout:                          4,
	IncomingConnectionsLimit:              10000, // Was -1
	IncomingMessageFilterBucketCount:      5,
	IncomingMessageFilterBucketSize:       512,
	LogSizeLimit:                          1073741824,
	NetAddress:                            "",
	NodeExporterListenAddress:             ":9100",
	NodeExporterPath:                      "./node_exporter",
	OutgoingMessageFilterBucketCount:      3,
	OutgoingMessageFilterBucketSize:       128,
	ReconnectTime:                         1 * time.Minute, // Was 60ns
	SuggestedFeeBlockHistory:              3,
	TxPoolExponentialIncreaseFactor:       2,
	TxPoolSize:                            50000,
	TxSyncIntervalSeconds:                 60,
	TxSyncTimeoutSeconds:                  30,
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
}

var defaultLocalV0 = Local{
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
	Version:                               0,
	Archival:                              false,
	BaseLoggerDebugLevel:                  1,
	CadaverSizeTarget:                     1073741824,
	CatchupFailurePeerRefreshRate:         10,
	DNSBootstrapID:                        "<network>.algorand.network",
	EnableIncomingMessageFilter:           false,
	EnableMetricReporting:                 false,
	EnableOutgoingNetworkMessageFiltering: true,
	EnableTopAccountsReporting:            false,
	EndpointAddress:                       "127.0.0.1:0",
	GossipFanout:                          4,
	IncomingConnectionsLimit:              -1,
	IncomingMessageFilterBucketCount:      5,
	IncomingMessageFilterBucketSize:       512,
	LogSizeLimit:                          1073741824,
	NetAddress:                            "",
	NodeExporterListenAddress:             ":9100",
	NodeExporterPath:                      "./node_exporter",
	OutgoingMessageFilterBucketCount:      3,
	OutgoingMessageFilterBucketSize:       128,
	ReconnectTime:                         60,
	SuggestedFeeBlockHistory:              3,
	TxPoolExponentialIncreaseFactor:       2,
	TxPoolSize:                            50000,
	TxSyncIntervalSeconds:                 60,
	TxSyncTimeoutSeconds:                  30,
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
}

func migrate(cfg Local) (newCfg Local, err error) {
	newCfg = cfg
	if cfg.Version == configVersion {
		return
	}

	if cfg.Version > configVersion {
		err = fmt.Errorf("unexpected config version: %d", cfg.Version)
		return
	}

	// For now, manually perform migration.
	// When we have more time, we can use reflection to migrate from initial
	// version to latest version (progressively applying defaults)
	// Migrate 0 -> 1
	if newCfg.Version == 0 {
		if newCfg.BaseLoggerDebugLevel == defaultLocalV0.BaseLoggerDebugLevel {
			newCfg.BaseLoggerDebugLevel = defaultLocalV1.BaseLoggerDebugLevel
		}
		if newCfg.IncomingConnectionsLimit == defaultLocalV0.IncomingConnectionsLimit {
			newCfg.IncomingConnectionsLimit = defaultLocalV1.IncomingConnectionsLimit
		}
		if newCfg.ReconnectTime == defaultLocalV0.ReconnectTime {
			newCfg.ReconnectTime = defaultLocalV1.ReconnectTime
		}
		newCfg.Version = 1
	}
	// Migrate 1 -> 2
	if newCfg.Version == 1 {
		if newCfg.ReservedFDs == defaultLocalV1.ReservedFDs {
			newCfg.ReservedFDs = defaultLocalV2.ReservedFDs
		}
		newCfg.Version = 2
	}
	// Migrate 2 -> 3
	if newCfg.Version == 2 {
		if newCfg.MaxConnectionsPerIP == defaultLocalV2.MaxConnectionsPerIP {
			newCfg.MaxConnectionsPerIP = defaultLocalV3.MaxConnectionsPerIP
		}
		if newCfg.CatchupParallelBlocks == defaultLocalV2.CatchupParallelBlocks {
			newCfg.CatchupParallelBlocks = defaultLocalV3.CatchupParallelBlocks
		}
		newCfg.Version = 3
	}
	// Migrate 3 -> 4
	if newCfg.Version == 3 {
		if newCfg.BroadcastConnectionsLimit == defaultLocalV3.BroadcastConnectionsLimit {
			newCfg.BroadcastConnectionsLimit = defaultLocalV4.BroadcastConnectionsLimit
		}
		if newCfg.AnnounceParticipationKey == defaultLocalV3.AnnounceParticipationKey {
			newCfg.AnnounceParticipationKey = defaultLocalV4.AnnounceParticipationKey
		}
		if newCfg.PriorityPeers == nil {
			newCfg.PriorityPeers = map[string]bool{}
		}
		newCfg.Version = 4
	}
	// Migrate 4 -> 5
	if newCfg.Version == 4 {
		if newCfg.TxPoolSize == defaultLocalV4.TxPoolSize {
			newCfg.TxPoolSize = defaultLocalV5.TxPoolSize
		}
		if newCfg.CatchupParallelBlocks == defaultLocalV4.CatchupParallelBlocks {
			newCfg.CatchupParallelBlocks = defaultLocalV5.CatchupParallelBlocks
		}
		if newCfg.PeerConnectionsUpdateInterval == defaultLocalV4.PeerConnectionsUpdateInterval {
			newCfg.PeerConnectionsUpdateInterval = defaultLocalV5.PeerConnectionsUpdateInterval
		}

		newCfg.Version = 5
	}

	// Migrate 5 -> 6
	if newCfg.Version == 5 {
		if newCfg.DNSSecurityFlags == 0 {
			newCfg.DNSSecurityFlags = defaultLocalV6.DNSSecurityFlags
		}
		if newCfg.EnablePingHandler == defaultLocalV5.EnablePingHandler {
			newCfg.EnablePingHandler = defaultLocalV6.EnablePingHandler
		}

		newCfg.Version = 6
	}

	if newCfg.Version != configVersion {
		err = fmt.Errorf("failed to migrate config version %d (stuck at %d) to latest %d", cfg.Version, newCfg.Version, configVersion)
	}
	return
}
