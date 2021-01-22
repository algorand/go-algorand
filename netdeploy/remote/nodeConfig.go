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

package remote

// NodeConfig represents the configuration settings to apply to a single node running on a host
type NodeConfig struct {
	Name               string `json:",omitempty"`
	Wallets            []NodeWalletData
	NetAddress         string `json:",omitempty"`
	APIEndpoint        string `json:",omitempty"`
	APIToken           string `json:",omitempty"`
	EnableTelemetry    bool   // Needs to also be configured host-wide (assign logging host name)
	TelemetryURI       string `json:",omitempty"` // Needs to be HostConfig
	EnableMetrics      bool   // Needs to also be configured host-wide (register DNS entry)
	MetricsURI         string `json:",omitempty"`
	EnableService      bool
	CronTabSchedule    string `json:",omitempty"`
	EnableBlockStats   bool
	DashboardEndpoint  string `json:",omitempty"`
	DeadlockOverride   int    `json:",omitempty"` // -1 = Disable deadlock detection, 0 = Use Default for build, 1 = Enable
	ConfigJSONOverride string `json:",omitempty"` // Raw json to merge into config.json after other modifications are complete

	// NodeNameMatchRegex is tested against Name in generated configs and if matched the rest of the configs in this record are applied as a template
	NodeNameMatchRegex string `json:",omitempty"`

	// FractionApply if > 0.0 is used as a probability of applying to generated nodes to use these values as a template
	FractionApply float64 `json:",omitempty"`

	// AltConfigs have other values for NodeNameMatchRegex or FractionApply. Typically the root NodeConfig is the default template and AltConfig contains variations that match some regex or are applied randomly to some fraction.
	// This should not be used recursively, but only one deep, a root and a list of alt configs.
	AltConfigs []NodeConfig `json:",omitempty"`
}

// IsRelay returns true if the node is configured to be a relay
func (nc NodeConfig) IsRelay() bool {
	// If we advertise to the world an address where we listen for gossip network connections, we are taking on the role of relay.
	return nc.NetAddress != ""
}

// NodeConfigGoal represents is a simplified version of NodeConfig used with 'goal network' commands
type NodeConfigGoal struct {
	Name              string
	IsRelay           bool `json:",omitempty"`
	Wallets           []NodeWalletData
	DeadlockDetection int `json:"-"`
}
