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
		Long:  "Run an automated test suite using the block-generator daemon and a provided algorand-indexer binary. Results are captured to a specified output directory.",
		Run: func(cmd *cobra.Command, args []string) {
			if err := Run(runnerArgs); err != nil {
				fmt.Println(err)
			}
		},
	}

	RunnerCmd.Flags().StringVarP(&runnerArgs.Path, "scenario", "s", "", "Directory containing scenarios, or specific scenario file.")
	RunnerCmd.Flags().StringVarP(&runnerArgs.IndexerBinary, "indexer-binary", "i", "", "Path to indexer binary.")
	RunnerCmd.Flags().Uint64VarP(&runnerArgs.IndexerPort, "indexer-port", "p", 4010, "Port to start the server at. This is useful if you have a prometheus server for collecting additional data.")
	RunnerCmd.Flags().StringVarP(&runnerArgs.PostgresConnectionString, "postgres-connection-string", "c", "", "Postgres connection string.")
	RunnerCmd.Flags().DurationVarP(&runnerArgs.RunDuration, "test-duration", "d", 5*time.Minute, "Duration to use for each scenario.")
	RunnerCmd.Flags().StringVarP(&runnerArgs.ReportDirectory, "report-directory", "r", "", "Location to place test reports.")
	RunnerCmd.Flags().StringVarP(&runnerArgs.LogLevel, "log-level", "l", "error", "LogLevel to use when starting Indexer. [error, warn, info, debug, trace]")
	RunnerCmd.Flags().StringVarP(&runnerArgs.CPUProfilePath, "cpuprofile", "", "", "Path where Indexer writes its CPU profile.")
	RunnerCmd.Flags().BoolVarP(&runnerArgs.ResetReportDir, "reset", "", false, "If set any existing report directory will be deleted before running tests.")
	RunnerCmd.Flags().BoolVarP(&runnerArgs.RunValidation, "validate", "", false, "If set the validator will run after test-duration has elapsed to verify data is correct. An extra line in each report indicates validator success or failure.")
	RunnerCmd.Flags().BoolVarP(&runnerArgs.KeepDataDir, "keep-data-dir", "k", false, "If set the validator will not delete the data directory after tests complete.")

	RunnerCmd.MarkFlagRequired("scenario")
	RunnerCmd.MarkFlagRequired("indexer-binary")
	RunnerCmd.MarkFlagRequired("postgres-connection-string")
	RunnerCmd.MarkFlagRequired("report-directory")
}
