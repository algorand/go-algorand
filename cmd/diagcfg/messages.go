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

const (
	loggingNotConfigured = "Remote logging is not currently configured and won't be enabled"
	loggingNotEnabled    = "Remote logging is currently disabled"
	loggingEnabled       = "Remote logging is enabled.  Node = %s, Guid = %s\n"

	metricNoConfig                          = "Unable to load configuration file : %s\n"
	metricConfigReadingFailed               = "Failed to read configuration file : %s\n"
	metricReportingStatus                   = "Metric reporting is %s\n"
	metricSaveConfigFailed                  = "Metric configuration file could not be saved : %s\n"
	metricFailedSetDNS                      = "Failed to store DNS : %s\n"
	metricCloudflareCredentialMissing       = "Cloudflare credentials are missing; Please configure environment variables CLOUDFLARE_ZONE_ID, CLOUDFLARE_EMAIL and CLOUDFLARE_AUTH_KEY"
	metricNoExternalHostAndFailedAutoDetect = "No external host name was provided, and auto-detecting external IP address failed : %v\n"
	metricNoExternalHostUsingAutoDetectedIP = "No external host name was provided; auto-detecting external IP address = %s\n"
	metricDataDirectoryEmpty                = "no data directory was specified. Please use either -d or set environment variable ALGORAND_DATA"

	telemetryConfigReadError = "Could not read telemetry config: %s\n"

	pathErrFormat = "%s: %s\n"
)
