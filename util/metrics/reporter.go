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

// Package metrics provides a metric logging wrappers for Prometheus server.
package metrics

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	// logging imports metrics so that we can have metrics about logging, which is more important than the four Debug lines we had here logging about metrics. TODO: find a more clever cycle resolution
	//"github.com/algorand/go-algorand/logging"
)

const (
	nodeExporterMetricsPath    = "/metrics"
	nodeExporterSyncAddr       = ":38086"
	nodeExporterRedirectOutput = false
)

// MetricReporter represent a single running metric server instance
type MetricReporter struct {
	serviceConfig     ServiceConfig
	nextAttempt       time.Time
	gatherInterval    time.Duration
	lastMetricsBuffer strings.Builder
	formattedLabels   string
	neSync            net.Listener // we will use this "locked" network port listener to syncronize which of the algod processes invokes the node_exporter
	neProcess         *os.Process  // a pointer to the node exporter process.
}

// MakeMetricReporter creates a new metrics server at the given endpoint.
func MakeMetricReporter(serviceConfig ServiceConfig) *MetricReporter {
	reporter := &MetricReporter{
		serviceConfig:  serviceConfig,
		gatherInterval: time.Duration(0),
	}
	reporter.createFormattedLabels()
	return reporter
}

func (reporter *MetricReporter) createFormattedLabels() {
	var buf strings.Builder
	if len(reporter.serviceConfig.Labels) == 0 {
		return
	}
	for k, v := range reporter.serviceConfig.Labels {
		buf.WriteString("," + k + "=\"" + v + "\"")
	}

	reporter.formattedLabels = buf.String()[1:]
}

// ReporterLoop is the main reporter loop. It waits until it receives a feedback from the node-exporter regarding the desired post-interval.
// then, it posts the collected metrics every such and such interval. Note that the context is used to "abort" this thread if needed.
func (reporter *MetricReporter) ReporterLoop(ctx context.Context) {
	defer reporter.tryDetachNodeExporter()
	reporter.nextAttempt = time.Now()
	for {
		// perform a small delay or wait until context expires.
		if !reporter.waitForTimeStamp(ctx) {
			// context expired, abort.
			return
		}
		// collect the metrics, but only once we've established a sampling rate.
		if reporter.gatherInterval != time.Duration(0) {
			reporter.gatherMetrics()
		}
		// post the collected metrics and retreive sampling rate.
		if !reporter.postGatheredMetrics(ctx) {
			// context expired, abort.
			return
		}
		// was the gatherInterval updated during postGatheredMetrics ?
		// ( the server reply include a header "SampleRate" which is used to update gatherInterval variable)
		if reporter.gatherInterval == time.Duration(0) {
			// wait arbitrary 2 seconds before keep going.
			reporter.nextAttempt = time.Now().Add(time.Duration(2) * time.Second)
		} else {
			// figure out when is the next time we're going to update the collected metrics.
			reporter.nextAttempt = time.Now().Add(reporter.gatherInterval)
		}
	}
}

// waitForTimeStamp blocks until the timestamp in nextAttempt arrives ( return true ) or the context expires ( return false ).
func (reporter *MetricReporter) waitForTimeStamp(ctx context.Context) bool {
	now := time.Now()
	if now.After(reporter.nextAttempt) {
		// we've already surpassed the time when we need to post again.
		return true
	}
	waitTime := reporter.nextAttempt.Sub(now)
	waitTimer := time.NewTimer(waitTime)
	select {
	case <-ctx.Done():
		waitTimer.Stop()
		return false
	case <-waitTimer.C:
		return true
	}
}

func (reporter *MetricReporter) gatherMetrics() {
	var buf strings.Builder
	DefaultRegistry().WriteMetrics(&buf, reporter.formattedLabels)
	reporter.lastMetricsBuffer = buf
}

func (reporter *MetricReporter) postGatheredMetrics(ctx context.Context) bool {
	request, err := http.NewRequest("POST", "http://"+reporter.serviceConfig.NodeExporterListenAddress+nodeExporterMetricsPath, strings.NewReader(reporter.lastMetricsBuffer.String()))
	if err != nil {
		// logging.Base().Debugf("Unable to post metrics to '%s'; error : '%v'", reporter.serviceConfig.NodeExporterListenAddress, err)
		return true
	}
	request = request.WithContext(ctx)
	var client http.Client
	resp, err := client.Do(request)
	if err == nil {
		reporter.parseSampleRate(resp)
	} else {
		// did we fail due to context expiration ?
		if ctx.Err() != nil {
			// we failed due to context reason.
			return false
		}
		// there was an error, but it wasn't due to expired context. We should try to invoke node_exporter, as needed.
		reporter.tryInvokeNodeExporter(ctx)
	}
	return true
}

func (reporter *MetricReporter) parseSampleRate(resp *http.Response) {
	// do we have the SampleRate header ?
	if strings, hasValue := resp.Header[http.CanonicalHeaderKey("SampleRate")]; hasValue {
		// we have the samplerate, we need to read it.
		if len(strings) == 0 {
			return
		}
		sampleRate, err := time.ParseDuration(strings[0] + "s")
		if err != nil {
			return
		}
		reporter.gatherInterval = sampleRate
	}
}

// tryDetachNodeExporter detaches itself from the existing node exporter process, if such was invoked by this algod instance.
func (reporter *MetricReporter) tryDetachNodeExporter() {
	proc := reporter.neProcess
	if proc != nil {
		proc.Release()
	}
	reporter.neProcess = nil
	// release the neSync lock..
	if reporter.neSync != nil {
		// close the socket, so that other process could take ownership.
		reporter.neSync.Close()
		reporter.neSync = nil
	}
}

// parseNodeExporterArgs parses the NodeExporterPath configuration string to extract Node Exporter's arguments.
func parseNodeExporterArgs(nodeExporterPath string, nodeExporterListenAddress string, nodeExporterMetricsPath string) []string {
	whitespaceRE := regexp.MustCompile(`\s+`)
	listenAddressRE := regexp.MustCompile(`--web.listen-address=(.+)`)
	telemetryPathRE := regexp.MustCompile(`--web.telemetry-path=(.+)`)
	vargs := whitespaceRE.Split(nodeExporterPath, -1)
	temp := vargs[:0]
	for _, varg := range vargs {
		if listenAddressRE.MatchString(varg) {
			nodeExporterListenAddress = listenAddressRE.FindStringSubmatch(varg)[1]
		} else if telemetryPathRE.MatchString(varg) {
			nodeExporterMetricsPath = telemetryPathRE.FindStringSubmatch(varg)[1]
		} else if varg == "" {
			continue
		} else {
			temp = append(temp, varg)
		}
	}
	vargs = append(vargs[:len(temp)],
		"--web.listen-address="+nodeExporterListenAddress,
		"--web.telemetry-path="+nodeExporterMetricsPath)
	return vargs
}

func (reporter *MetricReporter) tryInvokeNodeExporter(ctx context.Context) {
	var err error
	if nil == reporter.neSync {
		// try to create it.
		if reporter.neSync, err = net.Listen("tcp", nodeExporterSyncAddr); err != nil {
			// we couldn't get a hold of this port number; that's an expected behaviour for any algod instance that isn't the first one..
			return
		}
		// good ! we were able to obtain ownership of this port
	} else {
		// we already own this port. we need to check on the current status of node_exporter.
		if reporter.neProcess != nil {
			// process is already running.
			return
		}
	}
	// give the node exporter the same enviroment variable we've received.
	neAttributes := os.ProcAttr{
		Dir: filepath.Dir(os.Args[0]),
		Env: os.Environ(),
	}
	if nodeExporterRedirectOutput {
		neAttributes.Files = []*os.File{
			os.Stdin,
			os.Stdout,
			os.Stderr}
	}
	// prepare the vargs that the new process is going to have.
	vargs := parseNodeExporterArgs(reporter.serviceConfig.NodeExporterPath, reporter.serviceConfig.NodeExporterListenAddress, nodeExporterMetricsPath)
	// launch the process
	proc, err := os.StartProcess(vargs[0], vargs, &neAttributes)
	if err != nil {
		// logging.Base().Debugf("Unable to start node exporter : %v", err)
		return
	}
	// logging.Base().Debugf("Started node exporter with pid : %d", proc.Pid)

	reporter.neProcess = proc

	// wait for the process to complete on a separate goroutine, and set the reporter.neProcess varaible to nil once it's done.
	go func(proc **os.Process) {
		(*proc).Wait()
		// status, _ :=
		// logging.Base().Debugf("Node exporter process ended : %v", status)
		(*proc) = nil
	}(&reporter.neProcess)
	return
}
