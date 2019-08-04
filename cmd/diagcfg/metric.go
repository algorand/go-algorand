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

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/tools/network"
	"github.com/algorand/go-algorand/tools/network/cloudflare"
)

var (
	dataDir          string
	externalHostName string
)

func init() {
	metricCmd.AddCommand(metricStatusCmd)
	metricCmd.AddCommand(metricEnableCmd)
	metricCmd.AddCommand(metricDisableCmd)

	// override the data directory, if provided in the command.
	metricCmd.PersistentFlags().StringVarP(&dataDir, "dataDir", "d", os.ExpandEnv("$ALGORAND_DATA"), "Data directory")

	metricEnableCmd.Flags().StringVarP(&externalHostName, "externalHostName", "e", "", "External host name, such as relay-us-ea-3.algodev.network; will default to external IP Address if not specified")
	metricDisableCmd.Flags().StringVarP(&externalHostName, "externalHostName", "e", "", "External host name, such as relay-us-ea-3.algodev.network; will default to external IP Address if not specified")

}

var metricCmd = &cobra.Command{
	Use:   "metric -d dataDir",
	Short: "Control and manage Algorand metrics",
	Long:  `Enable/disable and configure Algorand remote logging`,
	Run:   metricStatusCmd.Run,
}

var metricStatusCmd = &cobra.Command{
	Use:   "status -d dataDir",
	Short: "Print the node's metric status",
	Long:  `Print the node's metric status`,
	Run: func(cmd *cobra.Command, args []string) {
		actualConfigPath, err := getConfigFilePath()
		if err != nil {
			fmt.Printf(metricNoConfig, fmt.Sprintf("%v", err))
			return
		}
		localConfig, err := config.LoadConfigFromDisk(actualConfigPath)
		if err != nil {
			fmt.Printf(metricConfigReadingFailed, fmt.Sprintf("%v", err))
			return
		}
		if localConfig.EnableMetricReporting {
			fmt.Printf(metricReportingStatus, "enabled")
		} else {
			fmt.Printf(metricReportingStatus, "disabled")
		}
	},
}

var metricEnableCmd = &cobra.Command{
	Use:   "enable -d dataDir -e externalHostName",
	Short: "Enable metric collection on node",
	Long:  `Enable metric collection on node`,
	Run: func(cmd *cobra.Command, args []string) {
		metricEnableDisable(true)
	},
}

var metricDisableCmd = &cobra.Command{
	Use:   "disable -d dataDir -e externalHostName",
	Short: "Disable metric collection on node",
	Long:  `Disable metric collection on node`,
	Run: func(cmd *cobra.Command, args []string) {
		metricEnableDisable(false)
	},
}

func metricEnableDisable(enable bool) {
	actualConfigPath, err := getConfigFilePath()
	if err != nil {
		fmt.Printf(metricNoConfig, fmt.Sprintf("%v", err))
		return
	}
	localConfig, err := config.LoadConfigFromDisk(actualConfigPath)
	if err != nil {
		fmt.Printf(metricConfigReadingFailed, fmt.Sprintf("%v", err))
		return
	}
	localConfig.EnableMetricReporting = enable
	err = localConfig.SaveToDisk(actualConfigPath)
	if err != nil {
		fmt.Printf(metricSaveConfigFailed, fmt.Sprintf("%v", err))
	}
	if !updateExternalHostName() {
		return
	}

	domainName := strings.Replace(localConfig.DNSBootstrapID, "<network>.", "", 1)
	cfZoneID, cfEmail, cfKey, err := getClouldflareCredentials()
	if err != nil {
		fmt.Printf(metricFailedSetDNS, fmt.Sprintf("%v", err))
		return
	}
	cloudflareDNS := cloudflare.NewDNS(cfZoneID, cfEmail, cfKey)
	if enable {
		port, err := strconv.ParseInt(strings.Split(localConfig.NodeExporterListenAddress, ":")[1], 10, 64)
		if err != nil {
			fmt.Printf(metricFailedSetDNS, fmt.Sprintf("%v", err))
			return
		}
		err = cloudflareDNS.SetSRVRecord(context.Background(), domainName, externalHostName, 1 /*ttl*/, 1 /*priority*/, uint(port) /*port*/, "_metrics", "_tcp", 1 /*weight*/)
	} else {
		err = cloudflareDNS.ClearSRVRecord(context.Background(), domainName, externalHostName, "_metrics", "_tcp")
	}

	if err != nil {
		fmt.Printf(metricFailedSetDNS, fmt.Sprintf("%v", err))
	}
}

func getConfigFilePath() (string, error) {
	maybeUpdateDataDirFromEnv()
	configFilePath := dataDir
	if configFilePath == "" {
		return "", fmt.Errorf("%s", metricDataDirectoryEmpty)
	}

	// check if directory exists.
	if configDirFile, err := os.Open(configFilePath); err == nil {
		configDirFile.Close()
	} else {
		return "", err
	}

	// check if actual file exists.
	if configFile, err := os.Open(filepath.Join(configFilePath, config.ConfigFilename)); err == nil {
		configFile.Close()
	} else {
		return "", err
	}
	return configFilePath, nil
}

func updateExternalHostName() bool {
	if externalHostName == "" {
		ipList, err := network.GetExternalIPAddress(context.Background())
		if err == nil && len(ipList) > 0 {
			externalHostName = ipList[0].String()
		} else {
			fmt.Printf(metricNoExternalHostAndFailedAutoDetect, err)
			return false
		}
		fmt.Printf(metricNoExternalHostUsingAutoDetectedIP, externalHostName)
	}
	return true
}

func getClouldflareCredentials() (string, string, string, error) {
	zoneID := os.Getenv("CLOUDFLARE_ZONE_ID")
	email := os.Getenv("CLOUDFLARE_EMAIL")
	authKey := os.Getenv("CLOUDFLARE_AUTH_KEY")
	if zoneID == "" || email == "" || authKey == "" {
		fmt.Println(metricCloudflareCredentialMissing)
		return "", "", "", fmt.Errorf("%s", metricCloudflareCredentialMissing)
	}
	return zoneID, email, authKey, nil
}
