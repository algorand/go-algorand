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

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/codecs"
)

// Local holds the per-node-instance configuration settings for the protocol.
// !!! WARNING !!!
//
// These versioned struct tags need to be maintained CAREFULLY and treated
// like UNIVERSAL CONSTANTS - they should not be modified once committed.
//
// New fields may be added to the Local struct, along with a version tag
// denoting a new version. When doing so, also update the
// test/testdata/configs/config-v{n}.json and call "make generate" to regenerate the constants.
//
// !!! WARNING !!!
type Local struct {
	// Version tracks the current version of the defaults so we can migrate old -> new
	// This is specifically important whenever we decide to change the default value
	// for an existing parameter. This field tag must be updated any time we add a new version.
	Version uint32 `version[0]:"0" version[1]:"1" version[2]:"2" version[3]:"3" version[4]:"4" version[5]:"5" version[6]:"6" version[7]:"7" version[8]:"8" version[9]:"9" version[10]:"10" version[11]:"11" version[12]:"12" version[13]:"13" version[14]:"14" version[15]:"15" version[16]:"16" version[17]:"17" version[18]:"18" version[19]:"19" version[20]:"20" version[21]:"21" version[22]:"22" version[23]:"23" version[24]:"24" version[25]:"25" version[26]:"26" version[27]:"27" version[28]:"28" version[29]:"29" version[30]:"30" version[31]:"31" version[32]:"32" version[33]:"33" version[34]:"34" version[35]:"35" version[36]:"36" version[37]:"37"`

	// Archival nodes retain a full copy of the block history. Non-Archival nodes will delete old blocks and only retain what's need to properly validate blockchain messages (the precise number of recent blocks depends on the consensus parameters. Currently the last 1321 blocks are required). This means that non-Archival nodes require significantly less storage than Archival nodes.  If setting this to true for the first time, the existing ledger may need to be deleted to get the historical values stored as the setting only affects current blocks forward. To do this, shutdown the node and delete all .sqlite files within the data/testnet-version directory, except the crash.sqlite file. Restart the node and wait for the node to sync.
	Archival bool `version[0]:"false"`

	// GossipFanout sets the maximum number of peers the node will connect to with outgoing connections. If the list of peers is less than this setting, fewer connections will be made. The node will not connect to the same peer multiple times (with outgoing connections).
	GossipFanout int `version[0]:"4"`

	// NetAddress is the address and/or port on which a node listens for incoming connections, or blank to ignore incoming connections. Specify an IP and port or just a port. For example, 127.0.0.1:0 will listen on a random port on the localhost.
	NetAddress string `version[0]:""`

	// ReconnectTime is deprecated and unused.
	ReconnectTime time.Duration `version[0]:"60" version[1]:"60000000000"`

	// PublicAddress is the public address to connect to that is advertised to other nodes.
	// For MainNet relays, make sure this entry includes the full SRV host name
	// plus the publicly-accessible port number.
	// A valid entry will avoid "self-gossip" and is used for identity exchange
	// to de-duplicate redundant connections
	PublicAddress string `version[0]:""`

	// MaxConnectionsPerIP is the maximum number of connections allowed per IP address.
	MaxConnectionsPerIP int `version[3]:"30" version[27]:"15" version[35]:"8"`

	// PeerPingPeriodSeconds is deprecated and unused.
	PeerPingPeriodSeconds int `version[0]:"0"`

	// TLSCertFile is the certificate file used for the websocket network if povided.
	TLSCertFile string `version[0]:""`

	// TLSKeyFile is the key file used for the websocket network if povided.
	TLSKeyFile string `version[0]:""`

	// BaseLoggerDebugLevel specifies the logging level for algod (node.log). The levels range from 0 (critical error / silent) to 5 (debug / verbose). The default value is 4 (‘Info’ - fairly verbose).
	BaseLoggerDebugLevel uint32 `version[0]:"1" version[1]:"4"`

	// CadaverSizeTarget specifies the maximum size of the agreement.cfv file in bytes. Once full the file will be renamed to agreement.archive.log and a new agreement.cdv will be created.
	CadaverSizeTarget uint64 `version[0]:"1073741824" version[24]:"0"`

	// if this is not set, MakeService will attempt to use ColdDataDir instead
	CadaverDirectory string `version[27]:""`

	// HotDataDir is an optional directory to store data that is frequently accessed by the node.
	// For isolation, the node will create a subdirectory in this location, named by the genesis-id of the network.
	// If not specified, the node will use the runtime supplied datadir to store this data.
	// Individual resources may have their own override specified, which would override this setting for that resource.
	// Setting HotDataDir to a dedicated high performance disk allows for basic disc tuning.
	HotDataDir string `version[31]:""`

	// ColdDataDir is an optional directory to store data that is infrequently accessed by the node.
	// For isolation, the node will create a subdirectory in this location, named by the genesis-id of the network.
	// If not specified, the node will use the runtime supplied datadir.
	// Individual resources may have their own override specified, which would override this setting for that resource.
	// Setting ColdDataDir to a less critical or cheaper disk allows for basic disc tuning.
	ColdDataDir string `version[31]:""`

	// TrackerDbDir is an optional directory to store the tracker database.
	// For isolation, the node will create a subdirectory in this location, named by the genesis-id of the network.
	// If not specified, the node will use the HotDataDir.
	TrackerDBDir string `version[31]:""`
	// BlockDBDir is an optional directory to store the block database.
	// For isolation, the node will create a subdirectory in this location, named by the genesis-id of the network.
	// If not specified, the node will use the ColdDataDir.
	BlockDBDir string `version[31]:""`
	// CatchpointDir is an optional directory to store catchpoint files,
	// except for the in-progress temp file, which will use the HotDataDir and is not separately configurable.
	// For isolation, the node will create a subdirectory in this location, named by the genesis-id of the network.
	// If not specified, the node will use the ColdDataDir.
	CatchpointDir string `version[31]:""`
	// StateproofDir is an optional directory to persist state about observed and issued state proof messages.
	// For isolation, the node will create a subdirectory in this location, named by the genesis-id of the network.
	// If not specified, the node will use the HotDataDir.
	StateproofDir string `version[31]:""`
	// CrashDBDir is an optional directory to persist agreement's consensus participation state.
	// For isolation, the node will create a subdirectory in this location, named by the genesis-id of the network.
	// If not specified, the node will use the HotDataDir
	CrashDBDir string `version[31]:""`

	// LogFileDir is an optional directory to store the log, node.log
	// If not specified, the node will use the HotDataDir.
	// The -o command line option can be used to override this output location.
	LogFileDir string `version[31]:""`
	// LogArchiveDir is an optional directory to store the log archive.
	// If not specified, the node will use the ColdDataDir.
	LogArchiveDir string `version[31]:""`

	// IncomingConnectionsLimit specifies the max number of incoming connections
	// for the gossip protocol configured in NetAddress. 0 means no connections allowed. Must be non-negative.
	// Estimating 1.5MB per incoming connection, 1.5MB*2400 = 3.6GB
	IncomingConnectionsLimit int `version[0]:"-1" version[1]:"10000" version[17]:"800" version[27]:"2400"`

	// P2PHybridIncomingConnectionsLimit is used as IncomingConnectionsLimit for P2P connections in hybrid mode.
	// For pure P2P nodes IncomingConnectionsLimit is used.
	P2PHybridIncomingConnectionsLimit int `version[34]:"1200"`

	// BroadcastConnectionsLimit specifies the number of connections that
	// will receive broadcast (gossip) messages from this node. If the
	// node has more connections than this number, it will send broadcasts
	// to the top connections by priority (outgoing connections first, then
	// by money held by peers based on their participation key). 0 means
	// no outgoing messages (not even transaction broadcasting to outgoing
	// peers). -1 means unbounded (default).
	BroadcastConnectionsLimit int `version[4]:"-1"`

	// AnnounceParticipationKey specifies that this node should announce its
	// participation key (with the largest stake) to its gossip peers.  This
	// allows peers to prioritize our connection, if necessary, in case of a
	// DoS attack.  Disabling this means that the peers will not have any
	// additional information to allow them to prioritize our connection.
	AnnounceParticipationKey bool `version[4]:"true"`

	// PriorityPeers specifies peer IP addresses that should always get
	// outgoing broadcast messages from this node.
	PriorityPeers map[string]bool `version[4]:""`

	// ReservedFDs is used to make sure the algod process does not run out of file descriptors (FDs). Algod ensures
	// that RLIMIT_NOFILE >= IncomingConnectionsLimit + RestConnectionsHardLimit +
	// ReservedFDs. ReservedFDs are meant to leave room for short-lived FDs like
	// DNS queries, SQLite files, etc. This parameter shouldn't be changed.
	// If RLIMIT_NOFILE < IncomingConnectionsLimit + RestConnectionsHardLimit + ReservedFDs
	// then either RestConnectionsHardLimit or IncomingConnectionsLimit decreased.
	ReservedFDs uint64 `version[2]:"256"`

	// EndpointAddress configures the address the node listens to for REST API calls. Specify an IP and port or just port. For example, 127.0.0.1:0 will listen on a random port on the localhost (preferring 8080).
	EndpointAddress string `version[0]:"127.0.0.1:0"`

	// Respond to Private Network Access preflight requests sent to the node. Useful when a public website is trying to access a node that's hosted on a local network.
	EnablePrivateNetworkAccessHeader bool `version[35]:"false"`

	// RestReadTimeoutSeconds is passed to the API servers rest http.Server implementation.
	RestReadTimeoutSeconds int `version[4]:"15"`

	// RestWriteTimeoutSeconds is passed to the API servers rest http.Server implementation.
	RestWriteTimeoutSeconds int `version[4]:"120"`

	// DNSBootstrapID specifies the names of a set of DNS SRV records that identify the set of nodes available to connect to.
	// This is applicable to both relay and archival nodes - they are assumed to use the same DNSBootstrapID today.
	// When resolving the bootstrap ID <network> will be replaced by the genesis block's network name. This string uses a URL
	// parsing library and supports optional backup and dedup parameters. 'backup' is used to provide a second DNS entry to use
	// in case the primary is unavailable. dedup is intended to be used to deduplicate SRV records returned from the primary
	// and backup DNS address. If the <name> macro is used in the dedup mask, it must be at the beginning of the expression.
	// This is not typically something a user would configure. For more information see config/dnsbootstrap.go.
	DNSBootstrapID string `version[0]:"<network>.algorand.network" version[28]:"<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)"`

	// LogSizeLimit is the log file size limit in bytes. When set to 0 logs will be written to stdout.
	LogSizeLimit uint64 `version[0]:"1073741824"`

	// LogArchiveName text/template for creating log archive filename.
	// Available template vars:
	// Time at start of log: {{.Year}} {{.Month}} {{.Day}} {{.Hour}} {{.Minute}} {{.Second}}
	// Time at end of log: {{.EndYear}} {{.EndMonth}} {{.EndDay}} {{.EndHour}} {{.EndMinute}} {{.EndSecond}}
	//
	// If the filename ends with .gz or .bz2 it will be compressed.
	//
	// default: "node.archive.log" (no rotation, clobbers previous archive)
	LogArchiveName string `version[4]:"node.archive.log"`

	// LogArchiveMaxAge will be parsed by time.ParseDuration().
	// Valid units are 's' seconds, 'm' minutes, 'h' hours
	LogArchiveMaxAge string `version[4]:""`

	// CatchupFailurePeerRefreshRate is the maximum number of consecutive attempts to catchup after which we replace the peers we're connected to.
	CatchupFailurePeerRefreshRate int `version[0]:"10"`

	// NodeExporterListenAddress is used to set the specific address for publishing metrics; the Prometheus server connects to this incoming port to retrieve metrics.
	NodeExporterListenAddress string `version[0]:":9100"`

	// EnableMetricReporting determines if the metrics service for a node is to be enabled. This setting controls metrics being collected from this specific instance of algod. If any instance has metrics enabled, machine-wide metrics are also collected.
	EnableMetricReporting bool `version[0]:"false"`

	// EnableTopAccountsReporting enable top accounts reporting flag. Deprecated, do not use.
	EnableTopAccountsReporting bool `version[0]:"false"`

	// EnableAgreementReporting controls the agreement reporting flag. Currently only prints additional period events.
	EnableAgreementReporting bool `version[3]:"false"`

	// EnableAgreementTimeMetrics controls the agreement timing metrics flag.
	EnableAgreementTimeMetrics bool `version[3]:"false"`

	// NodeExporterPath is the path to the node_exporter binary.
	NodeExporterPath string `version[0]:"./node_exporter"`

	// FallbackDNSResolverAddress defines the fallback DNS resolver address that would be used if the system resolver would fail to retrieve SRV records.
	FallbackDNSResolverAddress string `version[0]:""`

	// TxPoolExponentialIncreaseFactor exponential increase factor of transaction pool's fee threshold, should always be 2 in production.
	TxPoolExponentialIncreaseFactor uint64 `version[0]:"2"`

	// SuggestedFeeBlockHistory is deprecated and unused.
	SuggestedFeeBlockHistory int `version[0]:"3"`

	// TxBacklogServiceRateWindowSeconds is the window size used to determine the service rate of the txBacklog
	TxBacklogServiceRateWindowSeconds int `version[27]:"10"`

	// TxBacklogReservedCapacityPerPeer determines how much dedicated serving capacity the TxBacklog gives each peer
	TxBacklogReservedCapacityPerPeer int `version[27]:"20"`

	// TxBacklogAppTxRateLimiterMaxSize denotes a max size for the tx rate limiter
	// calculated as "a thousand apps on a network of thousand of peers"
	TxBacklogAppTxRateLimiterMaxSize int `version[32]:"1048576"`

	// TxBacklogAppTxPerSecondRate determines a target app per second rate for the app tx rate limiter
	TxBacklogAppTxPerSecondRate int `version[32]:"100"`

	// TxBacklogRateLimitingCongestionRatio determines the backlog filling threshold percentage at which the app limiter kicks in
	// or the tx backlog rate limiter kicks off.
	TxBacklogRateLimitingCongestionPct int `version[32]:"50"`

	// EnableTxBacklogAppRateLimiting controls if an app rate limiter should be attached to the tx backlog enqueue process
	EnableTxBacklogAppRateLimiting bool `version[32]:"true"`

	// TxBacklogAppRateLimitingCountERLDrops feeds messages dropped by the ERL congestion manager & rate limiter (enabled by
	// EnableTxBacklogRateLimiting) to the app rate limiter (enabled by EnableTxBacklogAppRateLimiting), so that all TX messages
	// are counted. This provides more accurate rate limiting for the app rate limiter, at the potential expense of additional
	// deserialization overhead.
	TxBacklogAppRateLimitingCountERLDrops bool `version[35]:"false"`

	// EnableTxBacklogRateLimiting controls if a rate limiter and congestion manager should be attached to the tx backlog enqueue process
	// if enabled, the over-all TXBacklog Size will be larger by MAX_PEERS*TxBacklogReservedCapacityPerPeer
	EnableTxBacklogRateLimiting bool `version[27]:"false" version[30]:"true"`

	// TxBacklogSize is the queue size used for receiving transactions. default of 26000 to approximate 1 block of transactions
	// if EnableTxBacklogRateLimiting enabled, the over-all size will be larger by MAX_PEERS*TxBacklogReservedCapacityPerPeer
	TxBacklogSize int `version[27]:"26000"`

	// TxPoolSize is the number of transactions in the transaction pool buffer.
	TxPoolSize int `version[0]:"50000" version[5]:"15000" version[23]:"75000"`

	// number of seconds allowed for syncing transactions
	TxSyncTimeoutSeconds int64 `version[0]:"30"`

	// TxSyncIntervalSeconds number of seconds between transaction synchronizations.
	TxSyncIntervalSeconds int64 `version[0]:"60"`

	// IncomingMessageFilterBucketCount is the number of incoming message hash buckets.
	IncomingMessageFilterBucketCount int `version[0]:"5"`

	// IncomingMessageFilterBucketSize is the size of each incoming message hash bucket.
	IncomingMessageFilterBucketSize int `version[0]:"512"`

	// OutgoingMessageFilterBucketCount is the number of outgoing message hash buckets.
	OutgoingMessageFilterBucketCount int `version[0]:"3"`

	// OutgoingMessageFilterBucketSize is the size of each outgoing message hash bucket.
	OutgoingMessageFilterBucketSize int `version[0]:"128"`

	// EnableOutgoingNetworkMessageFiltering enable the filtering of outgoing messages
	EnableOutgoingNetworkMessageFiltering bool `version[0]:"true"`

	// EnableIncomingMessageFilter enable the filtering of incoming messages.
	EnableIncomingMessageFilter bool `version[0]:"false"`

	// DeadlockDetection controls enabling or disabling deadlock detection.
	// negative (-1) to disable, positive (1) to enable, 0 for default.
	DeadlockDetection int `version[1]:"0"`

	// DeadlockDetectionThreshold is the threshold used for deadlock detection, in seconds.
	DeadlockDetectionThreshold int `version[20]:"30"`

	// RunHosted configures whether to run algod in Hosted mode (under algoh). Observed by `goal` for now.
	RunHosted bool `version[3]:"false"`

	// CatchupParallelBlocks is the maximum number of blocks that catchup will fetch in parallel.
	// If less than Protocol.SeedLookback, then Protocol.SeedLookback will be used as to limit the catchup.
	// Setting this variable to 0 would disable the catchup
	CatchupParallelBlocks uint64 `version[3]:"50" version[5]:"16"`

	// EnableAssembleStats specifies whether or not to emit the AssembleBlockMetrics telemetry event.
	EnableAssembleStats bool `version[0]:""`

	// EnableProcessBlockStats specifies whether or not to emit the ProcessBlockMetrics telemetry event.
	EnableProcessBlockStats bool `version[0]:""`

	// SuggestedFeeSlidingWindowSize is deprecated and unused.
	SuggestedFeeSlidingWindowSize uint32 `version[3]:"50"`

	// TxSyncServeResponseSize the max size the sync server would return.
	TxSyncServeResponseSize int `version[3]:"1000000"`

	// UseXForwardedForAddressField indicates whether or not the node should use the X-Forwarded-For HTTP Header when
	// determining the source of a connection.  If used, it should be set to the string "X-Forwarded-For", unless the
	// proxy vendor provides another header field.  In the case of CloudFlare proxy, the "CF-Connecting-IP" header
	// field can be used.
	// This setting does not support multiple X-Forwarded-For HTTP headers or multiple values in the header and always uses the last value
	// from the last X-Forwarded-For HTTP header that corresponds to a single reverse proxy (even if it received the request from another reverse proxy or adversary node).
	//
	// WARNING: By enabling this option, you are trusting peers to provide accurate forwarding addresses.
	// Bad actors can easily spoof these headers to circumvent this node's rate and connection limiting
	// logic. Do not enable this if your node is publicly reachable or used by untrusted parties.
	UseXForwardedForAddressField string `version[0]:""`

	// ForceRelayMessages indicates whether the network library should relay messages even in the case that no NetAddress was specified.
	ForceRelayMessages bool `version[0]:"false"`

	// ConnectionsRateLimitingWindowSeconds is being used along with ConnectionsRateLimitingCount;
	// see ConnectionsRateLimitingCount description for further information. Providing a zero value
	// in this variable disables the connection rate limiting.
	ConnectionsRateLimitingWindowSeconds uint `version[4]:"1"`

	// ConnectionsRateLimitingCount is being used along with ConnectionsRateLimitingWindowSeconds to determine if
	// a connection request should be accepted or not. The gossip network examines all the incoming requests in the past
	// ConnectionsRateLimitingWindowSeconds seconds that share the same origin. If the total count exceed the ConnectionsRateLimitingCount
	// value, the connection is refused.
	ConnectionsRateLimitingCount uint `version[4]:"60"`

	// EnableRequestLogger enabled the logging of the incoming requests to the telemetry server.
	EnableRequestLogger bool `version[4]:"false"`

	// PeerConnectionsUpdateInterval defines the interval at which the peer connections information is sent to
	// telemetry (when enabled). Defined in seconds.
	PeerConnectionsUpdateInterval int `version[5]:"3600"`

	// HeartbeatUpdateInterval defines the interval at which the heartbeat information is being sent to the
	// telemetry (when enabled). Defined in seconds. Minimum value is 60.
	HeartbeatUpdateInterval int `version[27]:"600"`

	// EnableProfiler enables the go pprof endpoints, should be false if
	// the algod api will be exposed to untrusted individuals
	EnableProfiler bool `version[0]:"false"`

	// EnableRuntimeMetrics exposes Go runtime metrics in /metrics and via node_exporter.
	EnableRuntimeMetrics bool `version[22]:"false"`

	// EnableNetDevMetrics exposes network interface total bytes sent/received metrics in /metrics
	EnableNetDevMetrics bool `version[34]:"false"`

	// TelemetryToLog configures whether to record messages to node.log that are normally only sent to remote event monitoring.
	TelemetryToLog bool `version[5]:"true"`

	// DNSSecurityFlags instructs algod validating DNS responses.
	// Possible fla values
	// 0x00 - disabled
	// 0x01 (dnssecSRV) - validate SRV response
	// 0x02 (dnssecRelayAddr) - validate relays' names to addresses resolution
	// 0x04 (dnssecTelemetryAddr) - validate telemetry and metrics names to addresses resolution
	// 0x08 (dnssecTXT) - validate TXT response
	// ...
	DNSSecurityFlags uint32 `version[6]:"1" version[34]:"9"`

	// EnablePingHandler controls whether the gossip node would respond to ping messages with a pong message.
	EnablePingHandler bool `version[6]:"true"`

	// DisableOutgoingConnectionThrottling disables the connection throttling of the network library, which
	// allow the network library to continuously disconnect relays based on their relative (and absolute) performance.
	DisableOutgoingConnectionThrottling bool `version[5]:"false"`

	// NetworkProtocolVersion overrides network protocol version ( if present )
	NetworkProtocolVersion string `version[6]:""`

	// CatchpointInterval sets the interval at which catchpoint are being generated. Setting this to 0 disables the catchpoint from being generated.
	// See CatchpointTracking for more details.
	CatchpointInterval uint64 `version[7]:"10000"`

	// CatchpointFileHistoryLength defines how many catchpoint files to store.
	// 0 means don't store any, -1 mean unlimited and positive number suggest the maximum number of most recent catchpoint files to store.
	CatchpointFileHistoryLength int `version[7]:"365"`

	// EnableGossipService enables the gossip network HTTP websockets endpoint. The functionality of this depends on NetAddress, which must also be provided.
	// This functionality is required for serving gossip traffic.
	EnableGossipService bool `version[33]:"true"`

	// EnableLedgerService enables the ledger serving service. The functionality of this depends on NetAddress, which must also be provided.
	// This functionality is required for the catchpoint catchup.
	EnableLedgerService bool `version[7]:"false"`

	// EnableBlockService controls whether to enables the block serving service. The functionality of this depends on NetAddress, which must also be provided.
	// This functionality is required for catchup.
	EnableBlockService bool `version[7]:"false"`

	// EnableGossipBlockService enables the block serving service over the gossip network. The functionality of this depends on NetAddress, which must also be provided.
	// This functionality is required for the relays to perform catchup from nodes.
	EnableGossipBlockService bool `version[8]:"true"`

	// CatchupHTTPBlockFetchTimeoutSec controls how long the http query for fetching a block from a relay would take before giving up and trying another relay.
	CatchupHTTPBlockFetchTimeoutSec int `version[9]:"4"`

	// CatchupGossipBlockFetchTimeoutSec controls how long the gossip query for fetching a block from a relay would take before giving up and trying another relay.
	CatchupGossipBlockFetchTimeoutSec int `version[9]:"4"`

	// CatchupLedgerDownloadRetryAttempts controls the number of attempt the ledger fetching would be attempted before giving up catching up to the provided catchpoint.
	CatchupLedgerDownloadRetryAttempts int `version[9]:"50"`

	// CatchupBlockDownloadRetryAttempts controls the number of attempts the block fetcher would make before giving up on a provided catchpoint.
	CatchupBlockDownloadRetryAttempts int `version[9]:"1000"`

	// EnableDeveloperAPI enables teal/compile and teal/dryrun API endpoints.
	// This functionality is disabled by default.
	EnableDeveloperAPI bool `version[9]:"false"`

	// OptimizeAccountsDatabaseOnStartup controls whether the accounts database would be optimized
	// on algod startup.
	OptimizeAccountsDatabaseOnStartup bool `version[10]:"false"`

	// CatchpointTracking determines if catchpoints are going to be tracked. The value is interpreted as follows:
	// A value of -1 means "don't track catchpoints".
	// A value of 1 means "track catchpoints as long as CatchpointInterval > 0".
	// A value of 2 means "track catchpoints and always generate catchpoint files as long as CatchpointInterval > 0".
	// A value of 0 means automatic, which is the default value. In this mode, a non archival node would not track the catchpoints, and an archival node would track the catchpoints as long as CatchpointInterval > 0.
	// Other values of CatchpointTracking would behave as if the default value was provided.
	CatchpointTracking int64 `version[11]:"0"`

	// LedgerSynchronousMode defines the synchronous mode used by the ledger database. The supported options are:
	// 0 - SQLite continues without syncing as soon as it has handed data off to the operating system.
	// 1 - SQLite database engine will still sync at the most critical moments, but less often than in FULL mode.
	// 2 - SQLite database engine will use the xSync method of the VFS to ensure that all content is safely written to the disk surface prior to continuing. On Mac OS, the data is additionally syncronized via fullfsync.
	// 3 - In addition to what being done in 2, it provides additional durability if the commit is followed closely by a power loss.
	// for further information see the description of SynchronousMode in dbutil.go
	LedgerSynchronousMode int `version[12]:"2"`

	// AccountsRebuildSynchronousMode defines the synchronous mode used by the ledger database while the account database is being rebuilt. This is not a typical operational use-case,
	// and is expected to happen only on either startup (after enabling the catchpoint interval, or on certain database upgrades) or during fast catchup. The values specified here
	// and their meanings are identical to the ones in LedgerSynchronousMode.
	AccountsRebuildSynchronousMode int `version[12]:"1"`

	// MaxCatchpointDownloadDuration defines the maximum duration a client will be keeping the outgoing connection of a catchpoint download request open for processing before
	// shutting it down. Networks that have large catchpoint files, slow connection or slow storage could be a good reason to increase this value. Note that this is a client-side only
	// configuration value, and it's independent of the actual catchpoint file size.
	MaxCatchpointDownloadDuration time.Duration `version[13]:"7200000000000" version[28]:"43200000000000"`

	// MinCatchpointFileDownloadBytesPerSecond defines the minimal download speed that would be considered to be "acceptable" by the catchpoint file fetcher, measured in bytes per seconds. If the
	// provided stream speed drops below this threshold, the connection would be recycled. Note that this field is evaluated per catchpoint "chunk" and not on it's own. If this field is zero,
	// the default of 20480 would be used.
	MinCatchpointFileDownloadBytesPerSecond uint64 `version[13]:"20480"`

	// NetworkMessageTraceServer is a host:port address to report graph propagation trace info to.
	NetworkMessageTraceServer string `version[13]:""`

	// VerifiedTranscationsCacheSize defines the number of transactions that the verified transactions cache would hold before cycling the cache storage in a round-robin fashion.
	VerifiedTranscationsCacheSize int `version[14]:"30000" version[23]:"150000"`

	// DisableLocalhostConnectionRateLimit controls whether the incoming connection rate limit would apply for
	// connections that are originating from the local machine. Setting this to "true", allow to create large
	// local-machine networks that won't trip the incoming connection limit observed by relays.
	DisableLocalhostConnectionRateLimit bool `version[16]:"true"`

	// BlockServiceCustomFallbackEndpoints is a comma delimited list of endpoints which the block service uses to
	// redirect the http requests to in case it does not have the round. If empty, the block service will return
	// StatusNotFound (404)
	BlockServiceCustomFallbackEndpoints string `version[16]:""`

	// CatchupBlockValidateMode is a development and testing configuration used by the catchup service.
	// It can be used to omit certain validations to speed up the catchup process, or to apply extra validations which are redundant in normal operation.
	// This field is a bit-field with:
	// bit 0: (default 0) 0: verify the block certificate; 1: skip this validation
	// bit 1: (default 0) 0: verify payset committed hash in block header matches payset hash; 1: skip this validation
	// bit 2: (default 0) 0: don't verify the transaction signatures on the block are valid; 1: verify the transaction signatures on block
	// bit 3: (default 0) 0: don't verify that the hash of the recomputed payset matches the hash of the payset committed in the block header; 1: do perform the above verification
	// Note: not all permutations of the above bitset are currently functional. In particular, the ones that are functional are:
	// 0  : default behavior.
	// 3  : speed up catchup by skipping necessary validations
	// 12 : perform all validation methods (normal and additional). These extra tests helps to verify the integrity of the compiled executable against
	//      previously used executabled, and would not provide any additional security guarantees.
	CatchupBlockValidateMode int `version[16]:"0"`

	// EnableAccountUpdatesStats specifies whether or not to emit the AccountUpdates telemetry event.
	EnableAccountUpdatesStats bool `version[16]:"false"`

	// AccountUpdatesStatsInterval is the time interval in nanoseconds between accountUpdates telemetry events.
	AccountUpdatesStatsInterval time.Duration `version[16]:"5000000000"`

	// ParticipationKeysRefreshInterval is the duration between two consecutive checks to see if new participation
	// keys have been placed on the genesis directory. Deprecated and unused.
	ParticipationKeysRefreshInterval time.Duration `version[16]:"60000000000"`

	// DisableNetworking disables all the incoming and outgoing communication a node would perform. This is useful
	// when we have a single-node private network, where there are no other nodes that need to be communicated with.
	// Features like catchpoint catchup would be rendered completely non-operational, and many of the node inner
	// working would be completely dis-functional.
	DisableNetworking bool `version[16]:"false"`

	// ForceFetchTransactions allows to explicitly configure a node to retrieve all the transactions
	// into it's transaction pool, even if those would not be required as the node doesn't
	// participate in consensus and is not used to relay transactions.
	ForceFetchTransactions bool `version[17]:"false"`

	// EnableVerbosedTransactionSyncLogging enables the transaction sync to write extensive
	// message exchange information to the log file. This option is disabled by default,
	// so that the log files would not grow too rapidly.
	EnableVerbosedTransactionSyncLogging bool `version[17]:"false"`

	// TransactionSyncDataExchangeRate overrides the auto-calculated data exchange rate between each
	// two peers. The unit of the data exchange rate is in bytes per second. Setting the value to
	// zero implies allowing the transaction sync to dynamically calculate the value.
	TransactionSyncDataExchangeRate uint64 `version[17]:"0"`

	// TransactionSyncSignificantMessageThreshold define the threshold used for a transaction sync
	// message before it can be used for calculating the data exchange rate. Setting this to zero
	// would use the default values. The threshold is defined in units of bytes.
	TransactionSyncSignificantMessageThreshold uint64 `version[17]:"0"`

	// ProposalAssemblyTime is the max amount of time to spend on generating a proposal block.
	ProposalAssemblyTime time.Duration `version[19]:"250000000" version[23]:"500000000"`

	// RestConnectionsSoftLimit is the maximum number of active requests the API server
	// When the number of http connections to the REST layer exceeds the soft limit,
	// we start returning http code 429 Too Many Requests.
	RestConnectionsSoftLimit uint64 `version[20]:"1024"`

	// RestConnectionsHardLimit is the maximum number of active connections the API server will accept before closing requests with no response.
	RestConnectionsHardLimit uint64 `version[20]:"2048"`

	// MaxAPIResourcesPerAccount sets the maximum total number of resources (created assets, created apps,
	// asset holdings, and application local state) per account that will be allowed in AccountInformation
	// REST API responses before returning a 400 Bad Request. Set zero for no limit.
	MaxAPIResourcesPerAccount uint64 `version[21]:"100000"`

	// AgreementIncomingVotesQueueLength sets the size of the buffer holding incoming votes.
	AgreementIncomingVotesQueueLength uint64 `version[21]:"10000" version[27]:"20000"`

	// AgreementIncomingProposalsQueueLength sets the size of the buffer holding incoming proposals.
	AgreementIncomingProposalsQueueLength uint64 `version[21]:"25" version[27]:"50"`

	// AgreementIncomingBundlesQueueLength sets the size of the buffer holding incoming bundles.
	AgreementIncomingBundlesQueueLength uint64 `version[21]:"7" version[27]:"15"`

	// MaxAcctLookback sets the maximum lookback range for account states,
	// i.e. the ledger can answer account states questions for the range Latest-MaxAcctLookback...Latest
	MaxAcctLookback uint64 `version[23]:"4"`

	// BlockHistoryLookback sets the max lookback range for block information.
	// i.e. the block DB can return transaction IDs for questions for the range Latest-MaxBlockHistoryLookback...Latest
	MaxBlockHistoryLookback uint64 `version[31]:"0"`

	// EnableUsageLog enables 10Hz log of CPU and RAM usage.
	// Also adds 'algod_ram_usage` (number of bytes in use) to /metrics
	EnableUsageLog bool `version[24]:"false"`

	// MaxAPIBoxPerApplication defines the maximum total number of boxes per application that will be returned
	// in GetApplicationBoxes REST API responses.
	MaxAPIBoxPerApplication uint64 `version[25]:"100000"`

	// TxIncomingFilteringFlags instructs algod filtering incoming tx messages
	// Flag values:
	// 0x00 - disabled
	// 0x01 (txFilterRawMsg) - check for raw tx message duplicates
	// 0x02 (txFilterCanonical) - check for canonical tx group duplicates
	TxIncomingFilteringFlags uint32 `version[26]:"1"`

	// EnableExperimentalAPI enables experimental API endpoint. Note that these endpoints have no
	// guarantees in terms of functionality or future support.
	EnableExperimentalAPI bool `version[26]:"false"`

	// DisableLedgerLRUCache disables LRU caches in ledger.
	// Setting it to TRUE might result in significant performance degradation
	// and SHOULD NOT be used for other reasons than testing.
	DisableLedgerLRUCache bool `version[27]:"false"`

	// EnableFollowMode launches the node in "follower" mode. This turns off the agreement service,
	// and APIs related to broadcasting transactions, and enables APIs which can retrieve detailed information
	// from ledger caches and can control the ledger round.
	EnableFollowMode bool `version[27]:"false"`

	// EnableTxnEvalTracer turns on features in the BlockEvaluator which collect data on transactions, exposing them via algod APIs.
	// It will store txn deltas created during block evaluation, potentially consuming much larger amounts of memory,
	EnableTxnEvalTracer bool `version[27]:"false"`

	// StorageEngine allows to control which type of storage to use for the ledger.
	// Available options are:
	// - sqlite (default)
	// - pebbledb (experimental, in development)
	StorageEngine string `version[28]:"sqlite"`

	// TxIncomingFilterMaxSize sets the maximum size for the de-duplication cache used by the incoming tx filter
	// only relevant if TxIncomingFilteringFlags is non-zero
	TxIncomingFilterMaxSize uint64 `version[28]:"500000"`

	// BlockServiceMemCap is the memory capacity in bytes which is allowed for the block service to use for HTTP block requests.
	// When it exceeds this capacity, it redirects the block requests to a different node
	BlockServiceMemCap uint64 `version[28]:"500000000"`

	// EnableP2P turns on the peer to peer network.
	// When both EnableP2P and EnableP2PHybridMode (below) are set, EnableP2PHybridMode takes precedence.
	EnableP2P bool `version[31]:"false"`

	// EnableP2PHybridMode turns on both websockets and P2P networking.
	// Enabling this setting also requires PublicAddress to be set.
	EnableP2PHybridMode bool `version[34]:"false"`

	// P2PHybridNetAddress sets the listen address used for P2P networking, if hybrid mode is set.
	P2PHybridNetAddress string `version[34]:""`

	// EnableDHT will turn on the hash table for use with capabilities advertisement
	EnableDHTProviders bool `version[34]:"false"`

	// P2PPersistPeerID will write the private key used for the node's PeerID to the P2PPrivateKeyLocation.
	// This is only used when P2PEnable is true. If P2PPrivateKey is not specified, it uses the default location.
	P2PPersistPeerID bool `version[29]:"false"`

	// P2PPrivateKeyLocation allows the user to specify a custom path to the private key used for the node's PeerID.
	// The private key provided must be an ed25519 private key.
	// This is only used when P2PEnable is true. If the parameter is not set, it uses the default location.
	P2PPrivateKeyLocation string `version[29]:""`

	// DisableAPIAuth turns off authentication for public (non-admin) API endpoints.
	DisableAPIAuth bool `version[30]:"false"`

	// GoMemLimit provides the Go runtime with a soft memory limit. The default behavior is no limit,
	// unless the GOMEMLIMIT environment variable is set.
	GoMemLimit uint64 `version[34]:"0"`

	// EnableVoteCompression controls whether vote compression is enabled for websocket networks
	EnableVoteCompression bool `version[36]:"true"`

	// EnableBatchVerification controls whether ed25519 batch verification is enabled
	EnableBatchVerification bool `version[37]:"true"`
}

// DNSBootstrapArray returns an array of one or more DNS Bootstrap identifiers
func (cfg Local) DNSBootstrapArray(networkID protocol.NetworkID) []*DNSBootstrap {
	// Should never return an error here, as the config has already been validated at init
	result, _ := cfg.internalValidateDNSBootstrapArray(networkID)

	return result
}

// ValidateDNSBootstrapArray returns an array of one or more DNS Bootstrap identifiers or an error if any
// one fails to parse
func (cfg Local) ValidateDNSBootstrapArray(networkID protocol.NetworkID) ([]*DNSBootstrap, error) {
	return cfg.internalValidateDNSBootstrapArray(networkID)
}

// internalValidateDNSBootstrapArray handles the base functionality of parsing the DNSBootstrapID string.
// The function will return an error on the first failure encountered, or an array of DNSBootstrap entries.
func (cfg Local) internalValidateDNSBootstrapArray(networkID protocol.NetworkID) (
	bootstrapArray []*DNSBootstrap, err error) {

	bootstrapStringArray := strings.SplitSeq(cfg.DNSBootstrapID, ";")
	for bootstrapString := range bootstrapStringArray {
		if len(strings.TrimSpace(bootstrapString)) == 0 {
			continue
		}

		bootstrapEntry, err1 := parseDNSBootstrap(bootstrapString, networkID, defaultLocal.DNSBootstrapID != cfg.DNSBootstrapID)
		if err1 != nil {
			return nil, err1
		}

		bootstrapArray = append(bootstrapArray, bootstrapEntry)
	}
	return
}

// SaveToDisk writes the non-default Local settings into a root/ConfigFilename file
func (cfg Local) SaveToDisk(root string) error {
	configpath := filepath.Join(root, ConfigFilename)
	filename := os.ExpandEnv(configpath)
	return cfg.SaveToFile(filename)
}

// SaveAllToDisk writes the all Local settings into a root/ConfigFilename file
func (cfg Local) SaveAllToDisk(root string) error {
	configPath := filepath.Join(root, ConfigFilename)
	filename := os.ExpandEnv(configPath)
	return codecs.SaveObjectToFile(filename, cfg, true)
}

// SaveToFile saves the config to a specific filename, allowing overriding the default name
func (cfg Local) SaveToFile(filename string) error {
	var alwaysInclude []string
	alwaysInclude = append(alwaysInclude, "Version")
	return codecs.SaveNonDefaultValuesToFile(filename, cfg, defaultLocal, alwaysInclude)
}

// DNSSecuritySRVEnforced returns true if SRV response verification enforced
func (cfg Local) DNSSecuritySRVEnforced() bool {
	return cfg.DNSSecurityFlags&dnssecSRV != 0
}

// DNSSecurityRelayAddrEnforced returns true if relay name to ip addr resolution enforced
func (cfg Local) DNSSecurityRelayAddrEnforced() bool {
	return cfg.DNSSecurityFlags&dnssecRelayAddr != 0
}

// DNSSecurityTelemetryAddrEnforced returns true if relay name to ip addr resolution enforced
func (cfg Local) DNSSecurityTelemetryAddrEnforced() bool {
	return cfg.DNSSecurityFlags&dnssecTelemetryAddr != 0
}

// DNSSecurityTXTEnforced returns true if TXT response verification enforced
func (cfg Local) DNSSecurityTXTEnforced() bool {
	return cfg.DNSSecurityFlags&dnssecTXT != 0
}

// CatchupVerifyCertificate returns true if certificate verification is needed
func (cfg Local) CatchupVerifyCertificate() bool {
	return cfg.CatchupBlockValidateMode&catchupValidationModeCertificate == 0
}

// CatchupVerifyPaysetHash returns true if payset hash verification is needed
func (cfg Local) CatchupVerifyPaysetHash() bool {
	return cfg.CatchupBlockValidateMode&catchupValidationModePaysetHash == 0
}

// CatchupVerifyTransactionSignatures returns true if transactions signature verification is needed
func (cfg Local) CatchupVerifyTransactionSignatures() bool {
	return cfg.CatchupBlockValidateMode&catchupValidationModeVerifyTransactionSignatures != 0
}

// CatchupVerifyApplyData returns true if verifying the ApplyData of the payset needed
func (cfg Local) CatchupVerifyApplyData() bool {
	return cfg.CatchupBlockValidateMode&catchupValidationModeVerifyApplyData != 0
}

// TxFilterRawMsgEnabled returns true if raw tx filtering is enabled
func (cfg Local) TxFilterRawMsgEnabled() bool {
	return cfg.TxIncomingFilteringFlags&txFilterRawMsg != 0
}

// TxFilterCanonicalEnabled returns true if canonical tx group filtering is enabled
func (cfg Local) TxFilterCanonicalEnabled() bool {
	return cfg.TxIncomingFilteringFlags&txFilterCanonical != 0
}

// IsGossipServer returns true if this node supposed to start websocket or p2p server
func (cfg Local) IsGossipServer() bool {
	return cfg.IsWsGossipServer() || cfg.IsP2PGossipServer()
}

// IsWsGossipServer returns true if a node is configured to run a listening ws net
func (cfg Local) IsWsGossipServer() bool {
	// 1. NetAddress is set and EnableP2P is not set
	// 2. NetAddress is set and EnableP2PHybridMode is set then EnableP2P is overridden  by EnableP2PHybridMode
	return cfg.NetAddress != "" && (!cfg.EnableP2P || cfg.EnableP2PHybridMode)
}

// IsP2PGossipServer returns true if a node is configured to run a listening p2p net
func (cfg Local) IsP2PGossipServer() bool {
	return (cfg.EnableP2P && !cfg.EnableP2PHybridMode && cfg.NetAddress != "") || (cfg.EnableP2PHybridMode && cfg.P2PHybridNetAddress != "")
}

// IsHybridServer returns true if a node configured to run a listening both ws and p2p networks
func (cfg Local) IsHybridServer() bool {
	return cfg.NetAddress != "" && cfg.P2PHybridNetAddress != "" && cfg.EnableP2PHybridMode
}

// ValidateP2PHybridConfig checks if both NetAddress and P2PHybridNetAddress are set or unset in hybrid mode.
func (cfg Local) ValidateP2PHybridConfig() error {
	if cfg.EnableP2PHybridMode {
		if cfg.NetAddress == "" && cfg.P2PHybridNetAddress != "" || cfg.NetAddress != "" && cfg.P2PHybridNetAddress == "" {
			return P2PHybridConfigError{
				msg: "P2PHybridMode requires both NetAddress and P2PHybridNetAddress to be set or unset",
			}
		}
		// In hybrid mode we want to prevent connections from the same node over both P2P and WS.
		// The only way it is supported at the moment is to use net identity challenge that is based on PublicAddress.
		if (cfg.NetAddress != "" || cfg.P2PHybridNetAddress != "") && cfg.PublicAddress == "" {
			return P2PHybridConfigError{msg: "PublicAddress must be specified when EnableP2PHybridMode is set"}
		}
	}
	return nil
}

// P2PHybridConfigError is an error type for P2PHybrid configuration issues
type P2PHybridConfigError struct {
	msg string
}

func (e P2PHybridConfigError) Error() string {
	return e.msg
}

// ensureAbsGenesisDir will convert a path to absolute, and will attempt to make a genesis directory there
func ensureAbsGenesisDir(path string, genesisID string) (string, error) {
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	genesisDir := filepath.Join(pathAbs, genesisID)
	err = os.MkdirAll(genesisDir, 0700)
	if err != nil && !os.IsExist(err) {
		return "", err
	}
	return genesisDir, nil
}

// ResolvedGenesisDirs is a collection of directories including Genesis ID
// Subdirectories for execution of a node
type ResolvedGenesisDirs struct {
	RootGenesisDir       string
	HotGenesisDir        string
	ColdGenesisDir       string
	TrackerGenesisDir    string
	BlockGenesisDir      string
	CatchpointGenesisDir string
	StateproofGenesisDir string
	CrashGenesisDir      string
}

// String returns the Genesis Directory values as a string
func (rgd ResolvedGenesisDirs) String() string {
	ret := ""
	ret += fmt.Sprintf("RootGenesisDir: %s\n", rgd.RootGenesisDir)
	ret += fmt.Sprintf("HotGenesisDir: %s\n", rgd.HotGenesisDir)
	ret += fmt.Sprintf("ColdGenesisDir: %s\n", rgd.ColdGenesisDir)
	ret += fmt.Sprintf("TrackerGenesisDir: %s\n", rgd.TrackerGenesisDir)
	ret += fmt.Sprintf("BlockGenesisDir: %s\n", rgd.BlockGenesisDir)
	ret += fmt.Sprintf("CatchpointGenesisDir: %s\n", rgd.CatchpointGenesisDir)
	ret += fmt.Sprintf("StateproofGenesisDir: %s\n", rgd.StateproofGenesisDir)
	ret += fmt.Sprintf("CrashGenesisDir: %s\n", rgd.CrashGenesisDir)
	return ret
}

// ResolveLogPaths will return the most appropriate location for liveLog and archive, given user config
func (cfg *Local) ResolveLogPaths(rootDir string) (liveLog, archive string) {
	// the default locations of log and archive are root
	liveLog = filepath.Join(rootDir, "node.log")
	archive = filepath.Join(rootDir, cfg.LogArchiveName)
	// if hot data dir is set, use it for the base of logs
	if cfg.HotDataDir != "" {
		liveLog = filepath.Join(cfg.HotDataDir, "node.log")
	}
	// if cold data dir is set, use it for the base of archives
	if cfg.ColdDataDir != "" {
		archive = filepath.Join(cfg.ColdDataDir, cfg.LogArchiveName)
	}
	// if LogFileDir is set, use it instead
	if cfg.LogFileDir != "" {
		liveLog = filepath.Join(cfg.LogFileDir, "node.log")
	}
	// if LogArchivePath is set, use it instead
	if cfg.LogArchiveDir != "" {
		archive = filepath.Join(cfg.LogArchiveDir, cfg.LogArchiveName)
	}
	return liveLog, archive
}

type logger interface {
	Infof(format string, args ...interface{})
}

// EnsureAndResolveGenesisDirs will resolve the supplied config paths to absolute paths, and will create the genesis directories of each
// returns a ResolvedGenesisDirs struct with the resolved paths for use during runtime
func (cfg *Local) EnsureAndResolveGenesisDirs(rootDir, genesisID string, logger logger) (ResolvedGenesisDirs, error) {
	var resolved ResolvedGenesisDirs
	var err error
	if rootDir != "" {
		resolved.RootGenesisDir, err = ensureAbsGenesisDir(rootDir, genesisID)
		if err != nil {
			return ResolvedGenesisDirs{}, err
		}
	} else {
		return ResolvedGenesisDirs{}, fmt.Errorf("rootDir is required")
	}
	// if HotDataDir is not set, use RootDataDir
	if cfg.HotDataDir != "" {
		resolved.HotGenesisDir, err = ensureAbsGenesisDir(cfg.HotDataDir, genesisID)
		if err != nil {
			return ResolvedGenesisDirs{}, err
		}
	} else {
		resolved.HotGenesisDir = resolved.RootGenesisDir
	}
	// if ColdDataDir is not set, use RootDataDir
	if cfg.ColdDataDir != "" {
		resolved.ColdGenesisDir, err = ensureAbsGenesisDir(cfg.ColdDataDir, genesisID)
		if err != nil {
			return ResolvedGenesisDirs{}, err
		}
	} else {
		resolved.ColdGenesisDir = resolved.RootGenesisDir
	}
	// if TrackerDBDir is not set, use HotDataDir
	if cfg.TrackerDBDir != "" {
		resolved.TrackerGenesisDir, err = ensureAbsGenesisDir(cfg.TrackerDBDir, genesisID)
		if err != nil {
			return ResolvedGenesisDirs{}, err
		}
	} else {
		resolved.TrackerGenesisDir = resolved.HotGenesisDir
	}
	// if BlockDBDir is not set, use ColdDataDir
	if cfg.BlockDBDir != "" {
		resolved.BlockGenesisDir, err = ensureAbsGenesisDir(cfg.BlockDBDir, genesisID)
		if err != nil {
			return ResolvedGenesisDirs{}, err
		}
	} else {
		resolved.BlockGenesisDir = resolved.ColdGenesisDir
	}
	// if CatchpointDir is not set, use ColdDataDir
	if cfg.CatchpointDir != "" {
		resolved.CatchpointGenesisDir, err = ensureAbsGenesisDir(cfg.CatchpointDir, genesisID)
		if err != nil {
			return ResolvedGenesisDirs{}, err
		}
	} else {
		resolved.CatchpointGenesisDir = resolved.ColdGenesisDir
	}
	// if StateproofDir is not set, use HotDataDir
	if cfg.StateproofDir != "" {
		resolved.StateproofGenesisDir, err = ensureAbsGenesisDir(cfg.StateproofDir, genesisID)
		if err != nil {
			return ResolvedGenesisDirs{}, err
		}
	} else {
		resolved.StateproofGenesisDir = resolved.HotGenesisDir
		// if separate HotDataDir and ColdDataDir was configured, but StateproofDir was not configured
		if resolved.ColdGenesisDir != resolved.HotGenesisDir {
			// move existing stateproof DB files from ColdDataDir to HotDataDir
			moveErr := moveDirIfExists(logger, resolved.ColdGenesisDir, resolved.HotGenesisDir, StateProofFileName, StateProofFileName+"-shm", StateProofFileName+"-wal")
			if moveErr != nil {
				return ResolvedGenesisDirs{}, fmt.Errorf("error moving stateproof DB files from ColdDataDir %s to HotDataDir %s: %v", resolved.ColdGenesisDir, resolved.HotGenesisDir, moveErr)
			}
		}
	}
	// if CrashDBDir is not set, use HotDataDir
	if cfg.CrashDBDir != "" {
		resolved.CrashGenesisDir, err = ensureAbsGenesisDir(cfg.CrashDBDir, genesisID)
		if err != nil {
			return ResolvedGenesisDirs{}, err
		}
	} else {
		resolved.CrashGenesisDir = resolved.HotGenesisDir
		// if separate HotDataDir and ColdDataDir was configured, but CrashDBDir was not configured
		if resolved.ColdGenesisDir != resolved.HotGenesisDir {
			// move existing crash DB files from ColdDataDir to HotDataDir
			moveErr := moveDirIfExists(logger, resolved.ColdGenesisDir, resolved.HotGenesisDir, CrashFilename, CrashFilename+"-shm", CrashFilename+"-wal")
			if moveErr != nil {
				return ResolvedGenesisDirs{}, fmt.Errorf("error moving crash DB files from ColdDataDir %s to HotDataDir %s: %v", resolved.ColdGenesisDir, resolved.HotGenesisDir, moveErr)
			}
		}
	}
	return resolved, nil
}

func moveDirIfExists(logger logger, srcdir, dstdir string, files ...string) error {
	// first, check if any files already exist in dstdir, and quit if so
	for _, file := range files {
		if _, err := os.Stat(filepath.Join(dstdir, file)); err == nil {
			return fmt.Errorf("destination file %s already exists, not overwriting", filepath.Join(dstdir, file))
		}
	}
	// then, check if any files exist in srcdir, and move them to dstdir
	for _, file := range files {
		if _, err := os.Stat(filepath.Join(srcdir, file)); err == nil {
			if err := util.MoveFile(filepath.Join(srcdir, file), filepath.Join(dstdir, file)); err != nil {
				return fmt.Errorf("failed to move file %s from %s to %s: %v", file, srcdir, dstdir, err)
			}
			logger.Infof("Moved DB file %s from ColdDataDir %s to HotDataDir %s", file, srcdir, dstdir)
		}
	}
	return nil
}

// AdjustConnectionLimits updates RestConnectionsSoftLimit, RestConnectionsHardLimit, IncomingConnectionsLimit
// if requiredFDs greater than maxFDs
func (cfg *Local) AdjustConnectionLimits(requiredFDs, maxFDs uint64) bool {
	if maxFDs >= requiredFDs {
		return false
	}
	const reservedRESTConns = 10
	diff := requiredFDs - maxFDs

	if cfg.RestConnectionsHardLimit <= diff+reservedRESTConns {
		restDelta := diff + reservedRESTConns - cfg.RestConnectionsHardLimit
		cfg.RestConnectionsHardLimit = reservedRESTConns
		splitRatio := 1
		if cfg.IsHybridServer() {
			// split the rest of the delta between ws and p2p evenly
			splitRatio = 2
		}
		if cfg.IsWsGossipServer() || cfg.IsP2PGossipServer() {
			if cfg.IncomingConnectionsLimit > int(restDelta) {
				cfg.IncomingConnectionsLimit -= int(restDelta) / splitRatio
			} else {
				cfg.IncomingConnectionsLimit = 0
			}
		}
		if cfg.IsHybridServer() {
			if cfg.P2PHybridIncomingConnectionsLimit > int(restDelta) {
				cfg.P2PHybridIncomingConnectionsLimit -= int(restDelta) / splitRatio
			} else {
				cfg.P2PHybridIncomingConnectionsLimit = 0
			}
		}
	} else {
		cfg.RestConnectionsHardLimit -= diff
	}

	if cfg.RestConnectionsSoftLimit > cfg.RestConnectionsHardLimit {
		cfg.RestConnectionsSoftLimit = cfg.RestConnectionsHardLimit
	}

	return true
}

// StoresCatchpoints returns true if the node is configured to store catchpoints
func (cfg *Local) StoresCatchpoints() bool {
	if cfg.CatchpointInterval <= 0 {
		return false
	}
	switch cfg.CatchpointTracking {
	case CatchpointTrackingModeUntracked:
		// No catchpoints.
	default:
		fallthrough
	case CatchpointTrackingModeAutomatic, CatchpointTrackingModeTracked:
		if cfg.Archival {
			return true
		}
	case CatchpointTrackingModeStored:
		return true
	}
	return false
}

// TracksCatchpoints returns true if the node is configured to track catchpoints
func (cfg *Local) TracksCatchpoints() bool {
	if cfg.StoresCatchpoints() {
		return true
	}
	if cfg.CatchpointTracking == CatchpointTrackingModeTracked && cfg.CatchpointInterval > 0 {
		return true
	}
	return false
}
