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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sort"

	// embed conduit template config file
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/tools/block-generator/generator"
	"github.com/algorand/go-algorand/tools/block-generator/util"
)

//go:embed template/conduit_pg_exporter.tmpl
var conduitPostgresConfigTmpl string

//go:embed template/conduit_file_exporter.tmpl
var conduitFileExporterConfigTmpl string

const pad = "  "

// Args are all the things needed to run a performance test.
type Args struct {
	// Path is a directory when passed to RunBatch, otherwise a file path.
	Path                     string
	ConduitBinary            string
	MetricsPort              uint64
	Template string
	PostgresConnectionString string
	CPUProfilePath           string
	RunDuration              time.Duration
	RunnerVerbose            bool
	ConduitLogLevel          string
	BaseReportDirectory      string
	ResetReportDir           bool
	RunValidation            bool
	KeepDataDir              bool
	GenesisFile              string
	ResetDB                  bool
	StartDelay               time.Duration
	Times                    uint64
}

type config struct {
	LogLevel                 string
	LogFile                  string
	MetricsPort              string
	AlgodNet                 string
	PostgresConnectionString string
}

// Run is a public helper to run the tests.
// The test will run against the generator configuration file specified by 'args.Path'.
// If 'args.Path' is a directory it should contain generator configuration files, a test will run using each file.
func Run(args Args) error {
	defer fmt.Println("Done running tests!")
	for i := uint64(0); i < args.Times; i++ {
		reportDirectory := args.BaseReportDirectory
		if args.Times != 1 {
			fmt.Println("* Starting test", i+1, "of", args.Times, "times")
			reportDirectory = fmt.Sprintf("%s_%d", args.BaseReportDirectory, i+1)
		}
		if _, err := os.Stat(reportDirectory); !os.IsNotExist(err) {
			if args.ResetReportDir {
				fmt.Printf("Resetting existing report directory '%s'\n", reportDirectory)
				if err := os.RemoveAll(reportDirectory); err != nil {
					return fmt.Errorf("failed to reset report directory: %w", err)
				}
			} else {
				return fmt.Errorf("report directory '%s' already exists", reportDirectory)
			}
		}
		err := os.Mkdir(reportDirectory, os.ModeDir|os.ModePerm)
		if err != nil {
			return err
		}

		err = filepath.Walk(args.Path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("run.go Run(): failed to walk path: %w", err)
			}
			// Ignore the directory
			if info.IsDir() {
				return nil
			}
			runnerArgs := args
			runnerArgs.Path = path
			fmt.Printf("%s----------------------------------------------------------------------\n", pad)
			fmt.Printf("%sRunning test for configuration: %s\n", pad, info.Name())
			fmt.Printf("%s----------------------------------------------------------------------\n", pad)
			return runnerArgs.run(reportDirectory)
		})
		if err != nil {
			return fmt.Errorf("failed to walk path: %w", err)
		}
	}
	return nil
}

func (r *Args) run(reportDirectory string) error {

	baseName := filepath.Base(r.Path)
	baseNameNoExt := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	reportfile := path.Join(reportDirectory, fmt.Sprintf("%s.report", baseNameNoExt))
	conduitlogfile := path.Join(reportDirectory, fmt.Sprintf("%s.conduit-log", baseNameNoExt))
	ledgerlogfile := path.Join(reportDirectory, fmt.Sprintf("%s.ledger-log", baseNameNoExt))
	dataDir := path.Join(reportDirectory, fmt.Sprintf("%s_data", baseNameNoExt))
	// create the data directory.
	if err := os.Mkdir(dataDir, os.ModeDir|os.ModePerm); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}
	if !r.KeepDataDir {
		defer os.RemoveAll(dataDir)
	}

	// This middleware allows us to lock the block endpoint
	var freezeMutex deadlock.Mutex
	blockMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			freezeMutex.Lock()
			defer freezeMutex.Unlock()
			next.ServeHTTP(w, r)
		})
	}
	// get next db round
	var nextRound uint64
	var err error
	switch r.Template {
	case "file-exporter":
		fmt.Printf("%sUsing File Exporter to persist blocks.\n", pad)
	case "postgres-exporter":
		fmt.Printf("%sUsing PostgreSQL Exporter to persist blocks.\n", pad)
		if r.ResetDB {
			fmt.Printf("%sPostgreSQL resetting.\n", pad)
			if err = util.EmptyDB(r.PostgresConnectionString); err != nil {
				return fmt.Errorf("emptyDB err: %w", err)
			}
			nextRound = 0
		} else {
			nextRound, err = util.GetNextRound(r.PostgresConnectionString)
			if err != nil && err == util.ErrorNotInitialized {
				nextRound = 0
			} else if err != nil {
				return fmt.Errorf("getNextRound err: %w", err)
			}
			fmt.Printf("%sPostgreSQL next round: %d\n", pad, nextRound)
		}
	default:
		// TODO: the default case should attempt to read the supplied template name as a file under ./template/
		return fmt.Errorf("unknown template type: %s", r.Template)
	}

	if r.StartDelay > 0 {
		fmt.Printf("%sSleeping for start delay: %s\n", pad, r.StartDelay)
		time.Sleep(r.StartDelay)
	}

	// Start services
	algodNet := fmt.Sprintf("localhost:%d", 11112)
	metricsNet := fmt.Sprintf("localhost:%d", r.MetricsPort)
	generatorShutdownFunc, _ := startGenerator(ledgerlogfile, r.Path, nextRound, r.GenesisFile, r.RunnerVerbose, algodNet, blockMiddleware)
	defer func() {
		// Shutdown generator.
		fmt.Printf("%sShutting down generator...\n", pad)
		if err := generatorShutdownFunc(); err != nil {
			fmt.Printf("failed to shutdown generator: %s\n", err)
		}
		fmt.Printf("%sGenerator shutdown complete\n", pad)
	}()

	// create conduit config from template
	var conduitConfigTmpl string
	switch r.Template {
	case "file-exporter":
		conduitConfigTmpl = conduitFileExporterConfigTmpl
	case "postgres-exporter":
		conduitConfigTmpl = conduitPostgresConfigTmpl
	default:
		return fmt.Errorf("unknown template type: %s", r.Template)
	}

	t, err := template.New("conduit").Parse(conduitConfigTmpl)
	if err != nil {
		return fmt.Errorf("unable to parse conduit config template: %w", err)
	}
	// create config file in the right data directory
	f, err := os.Create(path.Join(dataDir, "conduit.yml"))
	if err != nil {
		return fmt.Errorf("problem creating conduit.yml: %w", err)
	}
	defer f.Close()
	conduitConfig := config{
		LogLevel:                 r.ConduitLogLevel,
		LogFile:                  conduitlogfile,
		MetricsPort:              fmt.Sprintf(":%d", r.MetricsPort),
		AlgodNet:                 algodNet,
		PostgresConnectionString: r.PostgresConnectionString,
	}
	err = t.Execute(f, conduitConfig)
	if err != nil {
		return fmt.Errorf("problem executing template file: %w", err)
	}

	// Start conduit
	conduitShutdownFunc, err := startConduit(dataDir, r.ConduitBinary, nextRound)
	if err != nil {
		return fmt.Errorf("failed to start Conduit: %w", err)
	}
	defer func() {
		// Shutdown conduit
		fmt.Printf("%sShutting down Conduit...\n", pad)
		if sdErr := conduitShutdownFunc(); sdErr != nil {
			fmt.Printf("failed to shutdown Conduit: %s\n", sdErr)
		}
		fmt.Printf("%sConduit shutdown complete\n", pad)
	}()

	// Create the report file
	report, err := os.Create(reportfile)
	if err != nil {
		return fmt.Errorf("unable to create report: %w", err)
	}
	defer report.Close()

	// Run the test, collecting results.
	// check /metrics endpoint is available before running the test
	var resp *http.Response
	for retry := 0; retry < 10; retry++ {
		resp, err = http.Get(fmt.Sprintf("http://%s/metrics", metricsNet))
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("failed to query metrics endpoint: %w", err)
	}
	if err = r.runTest(report, metricsNet, algodNet); err != nil {
		return err
	}
	fmt.Printf("%sTest completed successfully\n", pad)

	return nil
}

type metricType int

const (
	rate metricType = iota
	intTotal
	floatTotal
)

// Helper to record metrics. Supports rates (sum/count) and counters.
func recordDataToWriter(start time.Time, entry Entry, prefix string, out io.Writer) error {
	var writeErrors []string
	var writeErr error
	record := func(prefix2, name string, t metricType) {
		key := fmt.Sprintf("%s%s_%s", prefix, prefix2, name)
		if err := recordMetricToWriter(entry, key, name, t, out); err != nil {
			writeErr = err
			writeErrors = append(writeErrors, name)
		}
	}

	record("_average", BlockImportTimeName, rate)
	record("_cumulative", BlockImportTimeName, floatTotal)
	record("_average", ImportedTxnsPerBlockName, rate)
	record("_cumulative", ImportedTxnsPerBlockName, intTotal)
	record("", ImportedRoundGaugeName, intTotal)

	if len(writeErrors) > 0 {
		return fmt.Errorf("error writing metrics (%s): %w", strings.Join(writeErrors, ", "), writeErr)
	}

	// Calculate import transactions per second.
	totalTxn, err := getMetric(entry, ImportedTxnsPerBlockName, false)
	if err != nil {
		return err
	}

	importTimeS, err := getMetric(entry, BlockImportTimeName, false)
	if err != nil {
		return err
	}
	tps := totalTxn / importTimeS
	key := "overall_transactions_per_second"
	msg := fmt.Sprintf("%s_%s:%.2f\n", prefix, key, tps)
	if _, err := fmt.Fprint(out, msg); err != nil {
		return fmt.Errorf("unable to write metric '%s': %w", key, err)
	}

	// Uptime
	key = "uptime_seconds"
	msg = fmt.Sprintf("%s_%s:%.2f\n", prefix, key, time.Since(start).Seconds())
	if _, err := fmt.Fprint(out, msg); err != nil {
		return fmt.Errorf("unable to write metric '%s': %w", key, err)
	}

	return nil
}

func recordMetricToWriter(entry Entry, outputKey, metricSuffix string, t metricType, out io.Writer) error {
	value, err := getMetric(entry, metricSuffix, t == rate)
	if err != nil {
		return err
	}

	var msg string
	if t == intTotal {
		msg = fmt.Sprintf("%s:%d\n", outputKey, uint64(value))
	} else {
		msg = fmt.Sprintf("%s:%.2f\n", outputKey, value)
	}

	if _, err := fmt.Fprint(out, msg); err != nil {
		return fmt.Errorf("unable to write metric '%s': %w", outputKey, err)
	}

	return nil
}

func getMetric(entry Entry, suffix string, rateMetric bool) (float64, error) {
	total := 0.0
	sum := 0.0
	count := 0.0
	hasSum := false
	hasCount := false
	hasTotal := false

	for _, metric := range entry.Data {
		var err error

		if strings.Contains(metric, suffix) {
			split := strings.Split(metric, " ")
			if len(split) != 2 {
				return 0.0, fmt.Errorf("unknown metric format, expected 'key value' received: %s", metric)
			}

			// Check for _sum / _count for summary (rateMetric) metrics.
			// Otherwise grab the total value.
			if strings.HasSuffix(split[0], "_sum") {
				sum, err = strconv.ParseFloat(split[1], 64)
				hasSum = true
			} else if strings.HasSuffix(split[0], "_count") {
				count, err = strconv.ParseFloat(split[1], 64)
				hasCount = true
			} else if strings.HasSuffix(split[0], suffix) {
				total, err = strconv.ParseFloat(split[1], 64)
				hasTotal = true
			}

			if err != nil {
				return 0.0, fmt.Errorf("unable to parse metric '%s': %w", metric, err)
			}

			if rateMetric && hasSum && hasCount {
				return sum / count, nil
			} else if !rateMetric {
				if hasSum {
					return sum, nil
				}
				if hasTotal {
					return total, nil
				}
			}
		}
	}

	return 0.0, fmt.Errorf("metric incomplete or not found: %s", suffix)
}

func writeReport(w io.Writer, scenario string, start time.Time, runDuration time.Duration, generatorReport generator.Report, collector *MetricsCollector) error {
	write := func(pattern string, parts ...any) error {
		str := fmt.Sprintf(pattern, parts...)
		if _, err := fmt.Fprint(w, str); err != nil {
			return fmt.Errorf("unable to write '%s': %w", str, err)
		}
		return nil
	}

	if err := write("scenario:%s\n", scenario); err != nil {
		return err
	}

	if err := write("test_duration_seconds:%d\n", uint64(runDuration.Seconds())); err != nil {
		return err
	}

	if err := write("test_duration_actual_seconds:%f\n", time.Since(start).Seconds()); err != nil {
		return err
	}

	if err := write("initial_round:%d\n", generatorReport.InitialRound); err != nil {
		return err
	}

	for metric, value := range generatorReport.Counters {
		if err := write("%s:%d\n", metric, value); err != nil {
			return err
		}
	}

	effects := generator.CumulativeEffects(generatorReport)
	keys := make([]string, 0, len(effects))
	for k := range effects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	allTxns := uint64(0)
	for _, metric := range keys {
		// Skip this one
		if metric == "genesis" {
			continue
		}
		txCount := effects[metric]
		allTxns += txCount
		str := fmt.Sprintf("transaction_%s_total:%d\n", metric, txCount)
		if _, err := fmt.Fprint(w, str); err != nil {
			return fmt.Errorf("unable to write '%s' metric: %w", str, err)
		}
	}
	str := fmt.Sprintf("transaction_%s_total:%d\n", "ALL", allTxns)
	if _, err := fmt.Fprint(w, str); err != nil {
		return fmt.Errorf("unable to write '%s' metric: %w", str, err)
	}

	// Record a rate from one of the first data points.
	if len(collector.Data) > 5 {
		if err := recordDataToWriter(start, collector.Data[2], "early", w); err != nil {
			return err
		}
	}

	// Also record the final metrics.
	if err := recordDataToWriter(start, collector.Data[len(collector.Data)-1], "final", w); err != nil {
		return err
	}

	return nil
}

// Run the test for 'RunDuration', collect metrics and write report to the report file.
func (r *Args) runTest(w io.Writer, metricsURL string, generatorURL string) error {
	collector := &MetricsCollector{MetricsURL: fmt.Sprintf("http://%s/metrics", metricsURL)}

	// Run for r.RunDuration
	start := time.Now()
	fmt.Printf("%sduration starting now: %s\n", pad, start)
	count := 1
	for time.Since(start) < r.RunDuration {
		time.Sleep(r.RunDuration / 10)
		fmt.Printf("%scollecting metrics (%d)\n", pad, count)

		if err := collector.Collect(AllMetricNames...); err != nil {
			return fmt.Errorf("problem collecting metrics (%d / %s): %w", count, time.Since(start), err)
		}
		count++
	}

	fmt.Printf("%scollecting final metrics\n", pad)
	if err := collector.Collect(AllMetricNames...); err != nil {
		return fmt.Errorf("problem collecting final metrics (%d / %s): %w", count, time.Since(start), err)
	}

	// get generator report
	scenario := path.Base(r.Path)
	resp, err := http.Get(fmt.Sprintf("http://%s/report", generatorURL))
	if err != nil {
		return fmt.Errorf("generator report query failed")
	}
	defer resp.Body.Close()
	var generatorReport generator.Report
	if err = json.NewDecoder(resp.Body).Decode(&generatorReport); err != nil {
		return fmt.Errorf("problem decoding generator report: %w", err)
	}

	// write report to file
	err = writeReport(w, scenario, start, r.RunDuration, generatorReport, collector)
	if err != nil {
		return fmt.Errorf("problem writing report: %w", err)
	}
	return nil
}

// startGenerator starts the generator server.
func startGenerator(ledgerLogFile, configFile string, dbround uint64, genesisFile string, verbose bool, addr string, blockMiddleware func(http.Handler) http.Handler) (func() error, generator.Generator) {
	f, err := os.OpenFile(ledgerLogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	util.MaybeFail(err, "unable to open ledger log file '%s'", ledgerLogFile)
	log := logging.NewLogger()
	log.SetLevel(logging.Info)
	log.SetOutput(f)

	// Start generator.
	server, generator := generator.MakeServerWithMiddleware(log, dbround, genesisFile, configFile, verbose, addr, blockMiddleware)

	// Start the server
	go func() {
		// always returns error. ErrServerClosed on graceful close
		fmt.Printf("%sgenerator serving on %s\n", pad, server.Addr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			util.MaybeFail(err, "ListenAndServe() failure to start with config file '%s'", configFile)
		}
	}()

	return func() error {
		// stop generator
		defer generator.Stop()
		// Shutdown blocks until the server has stopped.
		if err := server.Shutdown(context.Background()); err != nil {
			return fmt.Errorf("failed during generator graceful shutdown: %w", err)
		}
		return nil
	}, generator
}

// startConduit starts the conduit binary.
func startConduit(dataDir string, conduitBinary string, round uint64) (func() error, error) {
	fmt.Printf("%sConduit starting with data directory: %s\n", pad, dataDir)
	ctx, cf := context.WithCancel(context.Background())
	cmd := exec.CommandContext(
		ctx,
		conduitBinary,
		"-r", strconv.FormatUint(round, 10),
		"-d", dataDir,
	)
	cmd.WaitDelay = 5 * time.Second

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr // pass errors to Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failure calling Start(): %w", err)
	}
	// conduit doesn't have health check endpoint. so, no health check for now

	return func() error {
		cf()
		if err := cmd.Wait(); err != nil {
			fmt.Printf("%sConduit exiting: %s\n", pad, err)
		}
		return nil
	}, nil
}
