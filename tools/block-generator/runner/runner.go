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

package runner

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/spf13/cobra"
)

// RunnerCmd launches the block-generator test suite runner.
var RunnerCmd *cobra.Command

func init() {
	rand.Seed(12345)
	var runnerArgs Args

	RunnerCmd = &cobra.Command{
		Use:   "runner",
		Short: "Run test suite and collect results.",
		Long:  "Run an automated test suite using the block-generator daemon and a provided conduit binary. Results are captured to a specified output directory.",
		RunE: func(cmd *cobra.Command, args []string) error{
			fmt.Printf("starting block-generator runner with args: %+v\n", runnerArgs)

			if runnerArgs.Template == "postgres-exporter" && runnerArgs.PostgresConnectionString == "" {
				return fmt.Errorf("exporting to postgres requires that postgres-connection-string to be set")
			}

			return Run(runnerArgs)
		},
	}

	RunnerCmd.Flags().StringVarP(&runnerArgs.Path, "scenario", "s", "", "Directory containing scenarios, or specific scenario file.")
	RunnerCmd.Flags().StringVarP(&runnerArgs.ConduitBinary, "conduit-binary", "i", "", "Path to conduit binary.")
	RunnerCmd.Flags().Uint64VarP(&runnerArgs.MetricsPort, "metrics-port", "p", 9999, "Port to start the metrics server at.")
	RunnerCmd.Flags().StringVarP(&runnerArgs.Template, "template", "", "postgres-exporter", "Specify the conduit template to use. Choices are: file-exporter or postgres-exporter.")
	RunnerCmd.Flags().StringVarP(&runnerArgs.PostgresConnectionString, "postgres-connection-string", "c", "", "Postgres connection string.")
	RunnerCmd.Flags().DurationVarP(&runnerArgs.RunDuration, "test-duration", "d", 5*time.Minute, "Duration to use for each scenario.")
	RunnerCmd.Flags().StringVarP(&runnerArgs.BaseReportDirectory, "report-directory", "r", "", "Location to place test reports. If --times is used, this is the prefix for multiple report directories.")
	RunnerCmd.Flags().BoolVarP(&runnerArgs.RunnerVerbose, "verbose", "v", false, "If set the runner will print debugging information from the generator and ledger.")
	RunnerCmd.Flags().StringVarP(&runnerArgs.ConduitLogLevel, "conduit-log-level", "l", "error", "LogLevel to use when starting Conduit. [panic, fatal, error, warn, info, debug, trace]")
	RunnerCmd.Flags().StringVarP(&runnerArgs.CPUProfilePath, "cpuprofile", "", "", "Path where Conduit writes its CPU profile.")
	RunnerCmd.Flags().BoolVarP(&runnerArgs.ResetReportDir, "reset-report-dir", "", false, "If set any existing report directory will be deleted before running tests.")
	RunnerCmd.Flags().BoolVarP(&runnerArgs.RunValidation, "validate", "", false, "If set the validator will run after test-duration has elapsed to verify data is correct. An extra line in each report indicates validator success or failure.")
	RunnerCmd.Flags().BoolVarP(&runnerArgs.KeepDataDir, "keep-data-dir", "k", false, "If set the validator will not delete the data directory after tests complete.")
	RunnerCmd.Flags().StringVarP(&runnerArgs.GenesisFile, "genesis-file", "f", "", "file path to the genesis associated with the db snapshot")
	RunnerCmd.Flags().BoolVarP(&runnerArgs.ResetDB, "reset-db", "", false, "If set database will be deleted before running tests.")
	RunnerCmd.Flags().Uint64VarP(&runnerArgs.Times, "times", "t", 1, "Number of times to run the scenario(s).")
	RunnerCmd.Flags().DurationVarP(&runnerArgs.StartDelay, "start-delay", "", 0, "Duration to wait before starting a test scenario. This may be useful for snapshot tests where DB maintenance occurs after loading data.")

	RunnerCmd.MarkFlagRequired("scenario")
	RunnerCmd.MarkFlagRequired("conduit-binary")
	RunnerCmd.MarkFlagRequired("report-directory")
}
