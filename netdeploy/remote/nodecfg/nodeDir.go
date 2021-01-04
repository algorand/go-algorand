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

package nodecfg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/netdeploy/remote"
	"github.com/algorand/go-algorand/shared/algoh"
	"github.com/algorand/go-algorand/util/tokens"
)

type nodeDir struct {
	remote.NodeConfig
	dataDir      string
	config       config.Local
	delaySave    bool
	configurator *nodeConfigurator
}

// * Configure:
// 		* IsRelay
// 		* NetAddress
// 		* APIEndpoint
// 		* APIToken
// 		* EnableTelemetry
// 		* TelemetryURI
// 		* EnableMetrics
// 		* EnableService
// 		* CronTabSchedule
//		* EnableBlockStats
//		* DashboardEndpoint
//		* DeadlockOverride
func (nd *nodeDir) configure(dnsName string) (err error) {
	fmt.Fprintf(os.Stdout, "Configuring Node %s\n", nd.Name)
	if err = nd.configureRelay(nd.IsRelay()); err != nil {
		fmt.Fprintf(os.Stdout, "Error during configureRelay: %s\n", err)
		return
	}
	if err = nd.configureAPIEndpoint(nd.APIEndpoint); err != nil {
		fmt.Fprintf(os.Stdout, "Error during configureAPIEndpoint: %s\n", err)
		return
	}
	if err = nd.configureAPIToken(nd.APIToken); err != nil {
		fmt.Fprintf(os.Stdout, "Error during configureAPIToken: %s\n", err)
		return
	}
	if err = nd.configureTelemetry(nd.EnableTelemetry); err != nil {
		fmt.Fprintf(os.Stdout, "Error during configureTelemetry: %s\n", err)
		return
	}
	if err = nd.configureMetrics(nd.EnableMetrics, nd.MetricsURI); err != nil {
		fmt.Fprintf(os.Stdout, "Error during configureMetrics: %s\n", err)
		return
	}
	if err = nd.configureDeadlock(nd.DeadlockOverride); err != nil {
		fmt.Fprintf(os.Stdout, "Error during configureDeadlock: %s\n", err)
		return
	}
	if err = nd.configureAlgoh(nd.EnableBlockStats); err != nil {
		fmt.Fprintf(os.Stdout, "Error configuring algoh: %s\n", err)
		return
	}
	if err = nd.configureOverrides(nd.ConfigJSONOverride); err != nil {
		fmt.Fprintf(os.Stdout, "Error applying config.json overrides: %s\n", err)
		return
	}
	// Configure DNSBootstrap - if not otherwise set, use the algodev default: <network>.algodev.network
	if err = nd.configureDNSBootstrap(); err != nil {
		fmt.Fprintf(os.Stdout, "Error during configureDNSBootstrap: %s\n", err)
		return
	}
	// Do this after reconciling the DNSBootstrap ID because we'll extract the network name
	// from it (eg <network>.algoblah.network -> algoblah.network)
	if err = nd.configureNetAddress(); err != nil {
		fmt.Fprintf(os.Stdout, "Error during configureNetAddress: %s\n", err)
		return
	}
	fmt.Println("Done configuring node directory.")
	return
}

func (nd *nodeDir) isConfigLoaded() bool {
	return nd.config.GossipFanout != 0
}

func (nd *nodeDir) ensureConfig() (err error) {
	if nd.isConfigLoaded() {
		return
	}
	nd.config, err = config.LoadConfigFromDisk(nd.dataDir)
	if os.IsNotExist(err) {
		err = nil
	}
	return
}

func (nd *nodeDir) saveConfig() (err error) {
	if nd.delaySave {
		return nil
	}
	if !nd.isConfigLoaded() {
		return nil
	}
	err = nd.config.SaveToDisk(nd.dataDir)
	return
}

func (nd *nodeDir) configureRelay(enable bool) (err error) {
	if err = nd.ensureConfig(); err != nil {
		return
	}
	// Nothing extra to configure here - we'll ensure DNS and Bootstrap entries elsewhere
	err = nd.saveConfig()
	return
}

func (nd *nodeDir) configureNetAddress() (err error) {
	if err = nd.ensureConfig(); err != nil {
		return
	}
	fmt.Fprintf(os.Stdout, " - Assigning NetAddress: %s\n", nd.NetAddress)
	nd.config.NetAddress = nd.NetAddress
	if nd.IsRelay() && nd.NetAddress[0] == ':' {
		fmt.Fprintf(os.Stdout, " - adding to relay addresses\n")
		domainName := strings.Replace(nd.config.DNSBootstrapID, "<network>", string(nd.configurator.genesisData.Network), -1)
		nd.configurator.addRelaySrv(domainName, nd.NetAddress)
	}
	err = nd.saveConfig()
	return
}

func (nd *nodeDir) configureAPIEndpoint(address string) (err error) {
	if err = nd.ensureConfig(); err != nil {
		return
	}
	// Blank means leave default; if not blank and different from default, update it
	if address == "" || address == nd.config.EndpointAddress {
		return
	}
	fmt.Fprintf(os.Stdout, " - Assigning API Endpoint: %s\n", address)
	nd.config.EndpointAddress = address
	err = nd.saveConfig()
	return
}

func (nd *nodeDir) configureAPIToken(token string) (err error) {
	if token == "" {
		return
	}
	if err = nd.ensureConfig(); err != nil {
		return
	}
	fmt.Fprintf(os.Stdout, " - Assigning APIToken: %s\n", token)
	ioutil.WriteFile(filepath.Join(nd.dataDir, tokens.AlgodTokenFilename), []byte(token), 0600)
	err = nd.saveConfig()
	return
}

func (nd *nodeDir) configureTelemetry(enable bool) (err error) {
	cfg, created, cfgErr := logging.EnsureTelemetryConfigCreated(nil, "")
	if cfgErr != nil {
		return cfgErr
	}

	// Override default enabling of new telemetry config
	if created {
		cfg.Enable = false
	}

	telemetryURI := strings.Replace(nd.TelemetryURI, "<network>", string(nd.configurator.genesisData.Network), -1)
	if !strings.HasPrefix(telemetryURI, "http") {
		telemetryURI = "http://" + telemetryURI
	}

	if enable == cfg.Enable &&
		(nd.TelemetryURI == "" || telemetryURI == cfg.URI) &&
		cfg.Name == nd.configurator.config.Name {
		return
	}

	// For now, don't disable - otherwise we NEED to configure telemetry
	// for every node on the Host.
	if enable {
		fmt.Fprintf(os.Stdout, " - Configuring telemetry (%v) => %s\n", enable, telemetryURI)
		cfg.Enable = enable
	} else {
		fmt.Fprintf(os.Stdout, " - Configuring telemetry (%v) => %s\n (not disabling)", enable, telemetryURI)
	}
	if nd.TelemetryURI != "" {
		cfg.URI = telemetryURI
	}
	cfg.Name = nd.configurator.config.Name
	cfg.Save(cfg.FilePath)
	return
}

func (nd *nodeDir) configureMetrics(enable bool, address string) (err error) {
	if err = nd.ensureConfig(); err != nil {
		return
	}
	if nd.config.EnableMetricReporting == enable {
		return
	}
	nd.config.EnableMetricReporting = enable

	metricsURI := strings.Replace(address, "<network>", string(nd.configurator.genesisData.Network), -1)

	// turn URI into parsable URI with scheme
	if !strings.HasPrefix(metricsURI, "http") {
		metricsURI = "http://" + metricsURI
	}

	// Split URI into local listening port and external SRV record name
	metricsURL, err := url.Parse(metricsURI)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Error occurred parsing metrics URI (%s): %s", metricsURI, err)
		return
	}

	metricsPort := metricsURL.Port()
	if metricsPort != "" {
		nd.config.NodeExporterListenAddress = ":" + metricsPort
	}
	metricsSRV := metricsURL.Hostname()

	fmt.Fprintf(os.Stdout, " - Configuring metrics (%v) => %s - %s\n", enable, metricsSRV, nd.config.NodeExporterListenAddress)
	if nd.config.NodeExporterListenAddress != "" && nd.config.NodeExporterListenAddress[0] == ':' {
		nd.configurator.registerMetricsSrv(metricsSRV, nd.config.NodeExporterListenAddress)
	}
	err = nd.saveConfig()
	return
}

func (nd *nodeDir) configureDeadlock(value int) (err error) {
	if err = nd.ensureConfig(); err != nil {
		return
	}
	if value == nd.config.DeadlockDetection {
		return
	}
	fmt.Fprintf(os.Stdout, " - Updating DeadlockDetection: %v\n", value)
	nd.config.DeadlockDetection = value
	err = nd.saveConfig()
	return
}

func (nd *nodeDir) configureAlgoh(enableBlockStats bool) error {
	configFile := filepath.Join(nd.dataDir, algoh.ConfigFilename)
	config, err := algoh.LoadConfigFromFile(configFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error loading algoh configuration: %v", err)
	}
	if config.SendBlockStats != enableBlockStats {
		fmt.Fprintf(os.Stdout, " - Configuring algoh SendBlockStats (%v)\n", enableBlockStats)
		config.SendBlockStats = enableBlockStats
		return config.Save(configFile)
	}
	return nil
}

func (nd *nodeDir) configureOverrides(overrideJSON string) (err error) {
	if overrideJSON == "" {
		return
	}

	if err = nd.ensureConfig(); err != nil {
		return
	}

	reader := strings.NewReader(overrideJSON)
	dec := json.NewDecoder(reader)
	if err = dec.Decode(&nd.config); err != nil {
		return
	}

	fmt.Fprintf(os.Stdout, " - Merged config overrides: %s\n", overrideJSON)

	err = nd.saveConfig()
	return
}

func (nd *nodeDir) configureDNSBootstrap() (err error) {
	if err = nd.ensureConfig(); err != nil {
		return
	}

	if nd.config.DNSBootstrapID == config.GetDefaultLocal().DNSBootstrapID {
		nd.config.DNSBootstrapID = strings.Replace(nd.config.DNSBootstrapID, "algorand", "algodev", -1)
		err = nd.saveConfig()
	}
	return
}
