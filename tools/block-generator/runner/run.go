// Copyright (C) 2019-2023 Algorand, Inc.
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
	"sort"

	// embed conduit template config file
	_ "embed"
	"encoding/json"
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

	"github.com/algorand/go-algorand/tools/block-generator/generator"
	"github.com/algorand/go-algorand/tools/block-generator/util"
	"github.com/algorand/go-deadlock"
)

//go:embed template/conduit.yml.tmpl
var conduitConfigTmpl string

// Args are all the things needed to run a performance test.
type Args struct {
	// Path is a directory when passed to RunBatch, otherwise a file path.
	Path                     string
	ConduitBinary            string
	MetricsPort              uint64
	PostgresConnectionString string
	CPUProfilePath           string
	RunDuration              time.Duration
	RunnerVerbose            bool
	ConduitLogLevel          string
	ReportDirectory          string
	ResetReportDir           bool
	RunValidation            bool
	KeepDataDir              bool
	GenesisFile              string
	ResetDB                  bool
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
	if _, err := os.Stat(args.ReportDirectory); !os.IsNotExist(err) {
		if args.ResetReportDir {
			fmt.Printf("Resetting existing report directory '%s'\n", args.ReportDirectory)
			if err := os.RemoveAll(args.ReportDirectory); err != nil {
				return fmt.Errorf("failed to reset report directory: %w", err)
			}
		} else {
			return fmt.Errorf("report directory '%s' already exists", args.ReportDirectory)
		}
	}
	err := os.Mkdir(args.ReportDirectory, os.ModeDir|os.ModePerm)
	if err != nil {
		return err
	}

	defer fmt.Println("Done running tests!")
	return filepath.Walk(args.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("run.go Run(): failed to walk path: %w", err)
		}
		// Ignore the directory
		if info.IsDir() {
			return nil
		}
		runnerArgs := args
		runnerArgs.Path = path
		fmt.Printf("Running test for configuration '%s'\n", path)
		return runnerArgs.run()
	})
}

func (r *Args) run() error {
	baseName := filepath.Base(r.Path)
	baseNameNoExt := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	reportfile := path.Join(r.ReportDirectory, fmt.Sprintf("%s.report", baseNameNoExt))
	logfile := path.Join(r.ReportDirectory, fmt.Sprintf("%s.conduit-log", baseNameNoExt))
	dataDir := path.Join(r.ReportDirectory, fmt.Sprintf("%s_data", baseNameNoExt))
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
	if r.ResetDB {
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
	}
	// Start services
	algodNet := fmt.Sprintf("localhost:%d", 11112)
	metricsNet := fmt.Sprintf("localhost:%d", r.MetricsPort)
	generatorShutdownFunc, _ := startGenerator(r.Path, nextRound, r.GenesisFile, r.RunnerVerbose, algodNet, blockMiddleware)
	defer func() {
		// Shutdown generator.
		if err := generatorShutdownFunc(); err != nil {
			fmt.Printf("failed to shutdown generator: %s\n", err)
		}
	}()
	// get conduit config template
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

	conduitConfig := config{r.ConduitLogLevel, logfile,
		fmt.Sprintf(":%d", r.MetricsPort),
		algodNet, r.PostgresConnectionString,
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
		if sdErr := conduitShutdownFunc(); sdErr != nil {
			fmt.Printf("failed to shutdown Conduit: %s\n", sdErr)
		}
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

	return nil
}

type metricType int

const (
	rate metricType = iota
	intTotal
	floatTotal
)

// Helper to record metrics. Supports rates (sum/count) and counters.
func recordDataToFile(start time.Time, entry Entry, prefix string, out *os.File) error {
	var writeErrors []string
	var writeErr error
	record := func(prefix2, name string, t metricType) {
		key := fmt.Sprintf("%s%s_%s", prefix, prefix2, name)
		if err := recordMetricToFile(entry, key, name, t, out); err != nil {
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
	if _, err := out.WriteString(msg); err != nil {
		return fmt.Errorf("unable to write metric '%s': %w", key, err)
	}

	// Uptime
	key = "uptime_seconds"
	msg = fmt.Sprintf("%s_%s:%.2f\n", prefix, key, time.Since(start).Seconds())
	if _, err := out.WriteString(msg); err != nil {
		return fmt.Errorf("unable to write metric '%s': %w", key, err)
	}

	return nil
}

func recordMetricToFile(entry Entry, outputKey, metricSuffix string, t metricType, out *os.File) error {
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

	if _, err := out.WriteString(msg); err != nil {
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

// Run the test for 'RunDuration', collect metrics and write them to the 'ReportDirectory'
func (r *Args) runTest(report *os.File, metricsURL string, generatorURL string) error {
	collector := &MetricsCollector{MetricsURL: fmt.Sprintf("http://%s/metrics", metricsURL)}

	// Run for r.RunDuration
	start := time.Now()
	count := 1
	for time.Since(start) < r.RunDuration {
		time.Sleep(r.RunDuration / 10)

		if err := collector.Collect(AllMetricNames...); err != nil {
			return fmt.Errorf("problem collecting metrics (%d / %s): %w", count, time.Since(start), err)
		}
		count++
	}
	if err := collector.Collect(AllMetricNames...); err != nil {
		return fmt.Errorf("problem collecting final metrics (%d / %s): %w", count, time.Since(start), err)
	}

	// write scenario to report
	scenario := path.Base(r.Path)
	if _, err := report.WriteString(fmt.Sprintf("scenario:%s\n", scenario)); err != nil {
		return fmt.Errorf("unable to write scenario to report: %w", err)
	}
	// Collect results.
	durationStr := fmt.Sprintf("test_duration_seconds:%d\ntest_duration_actual_seconds:%f\n",
		uint64(r.RunDuration.Seconds()),
		time.Since(start).Seconds())
	if _, err := report.WriteString(durationStr); err != nil {
		return fmt.Errorf("unable to write duration metric: %w", err)
	}

	resp, err := http.Get(fmt.Sprintf("http://%s/report", generatorURL))
	if err != nil {
		return fmt.Errorf("generator report query failed")
	}
	defer resp.Body.Close()
	var generatorReport generator.Report
	if err = json.NewDecoder(resp.Body).Decode(&generatorReport); err != nil {
		return fmt.Errorf("problem decoding generator report: %w", err)
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
		if _, err = report.WriteString(str); err != nil {
			return fmt.Errorf("unable to write transaction_count metric: %w", err)
		}
	}
	str := fmt.Sprintf("transaction_%s_total:%d\n", "ALL", allTxns)
	if _, err = report.WriteString(str); err != nil {
		return fmt.Errorf("unable to write transaction_count metric: %w", err)
	}

	// Record a rate from one of the first data points.
	if len(collector.Data) > 5 {
		if err = recordDataToFile(start, collector.Data[2], "early", report); err != nil {
			return err
		}
	}

	// Also record the final metrics.
	if err = recordDataToFile(start, collector.Data[len(collector.Data)-1], "final", report); err != nil {
		return err
	}

	return nil
}

// startGenerator starts the generator server.
func startGenerator(configFile string, dbround uint64, genesisFile string, verbose bool, addr string, blockMiddleware func(http.Handler) http.Handler) (func() error, generator.Generator) {
	// Start generator.
	server, generator := generator.MakeServerWithMiddleware(dbround, genesisFile, configFile, verbose, addr, blockMiddleware)

	// Start the server
	go func() {
		// always returns error. ErrServerClosed on graceful close
		fmt.Printf("generator serving on %s\n", server.Addr)
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
	cmd := exec.Command(
		conduitBinary,
		"-r", strconv.FormatUint(round, 10),
		"-d", dataDir,
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failure calling Start(): %w", err)
	}
	// conduit doesn't have health check endpoint. so, no health check for now

	return func() error {
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			fmt.Printf("failed to kill conduit process: %s\n", err)
			if err := cmd.Process.Kill(); err != nil {
				return fmt.Errorf("failed to kill conduit process: %w", err)
			}
		}
		if err := cmd.Wait(); err != nil {
			fmt.Printf("exiting block generator runner: %s\n", err)
		}
		return nil
	}, nil
}
