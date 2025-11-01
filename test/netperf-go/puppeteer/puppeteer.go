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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type recipeStep struct {
	StepName string   `json:"StepName"`
	Commands []string `json:"Commands"`
	Disabled bool     `json:"Disabled"`
}

type termRule struct {
	Class             string `json:"Class"`
	Round             int    `json:"Round"`
	TimeoutSec        int    `json:"TimeoutSec"`
	RetestIntervalSec int    `json:"RetestIntervalSec"`
	TelemetryHostFile string `json:"TelemetryHostFile"`
}

type metricCollection struct {
	Class             string `json:"Class"`
	Name              string `json:"Name"`
	Query             string `json:"Query"`
	TelemetryHostFile string `json:"TelemetryHostFile"`
}

type session struct {
	Recipes           []string           `json:"Recipes"`
	DeploymentRecipe  []recipeStep       `json:"DeploymentRecipe"`
	TeardownRecipe    []recipeStep       `json:"TeardownRecipe"`
	TerminationRules  []termRule         `json:"TerminationRules"`
	MetricsCollection []metricCollection `json:"MetricsCollection"`
}

type puppet struct {
	recipeIdx        int
	recipeFile       string
	recipeName       string
	channel          string
	s                *session
	networkName      string
	algonetDirectory string
	metrics          map[string]float64
}

func puppeteer(channel, jsonFile string) error {
	jsonBytes, err := os.ReadFile(jsonFile)
	if err != nil {
		return err
	}
	var s session
	err = json.Unmarshal([]byte(jsonBytes), &s)
	if err != nil {
		return err
	}

	// get the json directory path.
	jsonDirectory, err := filepath.Abs(jsonFile)
	if err != nil {
		return err
	}
	jsonDirectory, _ = filepath.Split(jsonDirectory)

	var wg sync.WaitGroup
	errors := make(chan error, len(s.Recipes))
	fmt.Printf("%d network recipes found\n", len(s.Recipes))
	wg.Add(len(s.Recipes))
	puppets := make([]*puppet, 0)
	for i, recipeName := range s.Recipes {
		p := &puppet{
			recipeIdx:  i,
			recipeFile: filepath.Join(jsonDirectory, recipeName),
			channel:    channel,
			s:          &s,
			metrics:    make(map[string]float64),
		}
		_, p.recipeName = filepath.Split(p.recipeFile)
		puppets = append(puppets, p)
		go p.exec(&wg, errors)
	}
	wg.Wait()
	select {
	case err := <-errors:
		return err
	default:
	}

	// print out all metrics.
	printMetrics(puppets)

	return nil
}

func printMetrics(puppets []*puppet) {
	totalWidth := 0
	header := ""
	for _, puppet := range puppets {
		totalWidth += len(puppet.recipeName) + 3
		header += "| " + puppet.recipeName + " "
	}
	header += "|"
	totalWidth++

	maxMetricNameWidth := 0
	uniqueMetricsNames := make(map[string]struct{})
	for _, puppet := range puppets {
		for metric := range puppet.metrics {
			if len(metric) > maxMetricNameWidth {
				maxMetricNameWidth = len(metric)
			}
			uniqueMetricsNames[metric] = struct{}{}
		}
	}
	metricNames := make([]string, 0)
	for metricName := range uniqueMetricsNames {
		metricNames = append(metricNames, metricName)
	}
	sort.Strings(metricNames)

	fmt.Printf("%s%s\n%s\n", strings.Repeat(" ", maxMetricNameWidth+1), header, strings.Repeat("-", totalWidth+maxMetricNameWidth+1))

	for _, metricName := range metricNames {
		line := fmt.Sprintf("%s%s", metricName, strings.Repeat(" ", maxMetricNameWidth-len(metricName)+1))
		for _, puppet := range puppets {
			fmtMetric := ""
			metricVal, has := puppet.metrics[metricName]
			if has {
				// we want to format metric.
				fmtMetric = fmt.Sprintf("%d", int(metricVal))
			}
			for len(fmtMetric) < len(puppet.recipeName)+2 {
				fmtMetric = " " + fmtMetric
				if len(fmtMetric) == len(puppet.recipeName)+2 {
					break
				}
				fmtMetric = fmtMetric + " "
			}
			line = fmt.Sprintf("%s|%s", line, fmtMetric)
		}

		fmt.Printf("%s|\n", line)
	}
}

func (p *puppet) exec(wg *sync.WaitGroup, errs chan error) {
	defer wg.Done()
	var algonetRootDir string
	if stageDir == "" {
		algonetRootDir = os.TempDir()
	} else {
		algonetRootDir = stageDir
	}
	p.algonetDirectory = path.Join(algonetRootDir, fmt.Sprintf("%s-%s", channel, p.recipeName))
	fmt.Printf("%s: Creating a temporary algonet directory '%s'\n", p.recipeName, p.algonetDirectory)

	if !skipReset {
		os.RemoveAll(p.algonetDirectory) // ignore errors.
	}

	err := os.MkdirAll(p.algonetDirectory, 0700)
	if err != nil {
		errs <- fmt.Errorf("Failed to create temporary algonet directory '%s' : %v", p.algonetDirectory, err)
		return
	}
	// I'm not sure why this required, but it won't have write permission otherwise.
	os.Chmod(p.algonetDirectory, 0700)

	p.networkName = fmt.Sprintf("pupp-%s-%d", channel, p.recipeIdx)

	// run the deployment recepie:
	for _, recipeStep := range p.s.DeploymentRecipe {
		if recipeStep.Disabled {
			fmt.Printf("%s: Disabled step '%s' skipped.\n", p.recipeName, recipeStep.StepName)
			continue
		}
		err1 := p.runStep(recipeStep, time.Hour)
		if err1 != nil {
			errs <- fmt.Errorf("Failed running recipe step '%s' : %v", recipeStep.StepName, err1)
			return
		}
	}

	p.wait()

	p.collectMetrics()

	// run the teardown recepie:
	for _, recipeStep := range p.s.TeardownRecipe {
		if recipeStep.Disabled {
			fmt.Printf("%s: Disabled step '%s' skipped.\n", p.recipeName, recipeStep.StepName)
			continue
		}
		err1 := p.runStep(recipeStep, time.Hour)
		if err1 != nil {
			errs <- fmt.Errorf("Failed running teardown step '%s' : %v", recipeStep.StepName, err1)
			return
		}
	}

	if !skipCleanup {
		// deleting algonet temporary directories
		err = os.RemoveAll(p.algonetDirectory)
		if err != nil {
			errs <- fmt.Errorf("Failed to removing temporary algonet directory '%s' post teardown: %v", p.algonetDirectory, err)
			return
		}
	}
}

type stdWriter struct {
	prefix  string
	output  string
	outFile *os.File
}

func (c *stdWriter) Write(p []byte) (n int, err error) {
	s := string(p)
	c.output += s
	for {
		eolIdx := strings.Index(c.output, "\n")
		if eolIdx == -1 {
			eolIdx = strings.Index(c.output, "\r")
		}
		if eolIdx == 0 {
			c.output = c.output[1:]
			continue
		}
		if eolIdx > 0 {
			line := c.prefix + c.output[:eolIdx+1]
			c.output = c.output[eolIdx+1:]
			fmt.Fprint(c.outFile, line)
		} else {
			break
		}
	}
	return len(p), nil
}

func parseCommandLine(command string) ([]string, error) {
	var args []string
	state := "start"
	current := ""
	quote := "\""
	escapeNext := true
	for i := 0; i < len(command); i++ {
		c := command[i]

		if state == "quotes" {
			if string(c) != quote {
				current += string(c)
			} else {
				args = append(args, current)
				current = ""
				state = "start"
			}
			continue
		}

		if escapeNext {
			current += string(c)
			escapeNext = false
			continue
		}

		if c == '\\' {
			escapeNext = true
			continue
		}

		if c == '"' || c == '\'' {
			state = "quotes"
			quote = string(c)
			continue
		}

		if state == "arg" {
			if c == ' ' || c == '\t' {
				args = append(args, current)
				current = ""
				state = "start"
			} else {
				current += string(c)
			}
			continue
		}

		if c != ' ' && c != '\t' {
			state = "arg"
			current += string(c)
		}
	}

	if state == "quotes" {
		return []string{}, fmt.Errorf("unclosed quote in command line: %s", command)
	}

	if current != "" {
		args = append(args, current)
	}

	return args, nil
}

func (p *puppet) runStep(recipeStep recipeStep, timeout time.Duration) error {
	fmt.Printf("%s: Running '%s'...\n", p.recipeName, recipeStep.StepName)

	ctx, cancelFnc := context.WithTimeout(context.Background(), timeout)
	defer cancelFnc()

	for _, command := range recipeStep.Commands {
		cmdTxt := strings.Replace(command, "<network>", p.networkName, -1)
		cmdTxt = strings.Replace(cmdTxt, "<channel>", channel, -1)
		cmdTxt = strings.Replace(cmdTxt, "<recipe>", p.recipeFile, -1)
		cmdTxt = strings.Replace(cmdTxt, "<for>", deployFor, -1)
		cmdTxt = os.ExpandEnv(cmdTxt)
		cmds, err := parseCommandLine(cmdTxt)
		if err != nil {
			return err
		}

		cmd := exec.CommandContext(ctx, cmds[0], cmds[1:]...)
		cmd.Dir = p.algonetDirectory
		cmd.Env = os.Environ()
		// the `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` is a workaround for MacOS only.
		// it doesn't do much on linux. see https://github.com/ansible/ansible/issues/32499 for details.
		cmd.Env = append(cmd.Env, "OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES")

		errorOutput := stdWriter{
			prefix:  p.recipeName + " : ",
			outFile: os.Stderr,
		}
		var output io.Writer
		if verbose {
			output = &stdWriter{
				prefix:  p.recipeName + " : ",
				outFile: os.Stdout,
			}
		} else {
			output = io.Discard
		}

		cmd.Stderr = &errorOutput
		cmd.Stdout = output
		err = cmd.Run()
		if err != nil {
			err = fmt.Errorf("cwd = %s command = %s Error = %v", p.algonetDirectory, cmdTxt, err)
			return err
		}
		output.Write([]byte("\n"))
		errorOutput.Write([]byte("\n"))

	}

	return nil
}

func (p *puppet) wait() {
	var timeout time.Duration
	var round uint64
	var retestInterval time.Duration
	var rndPoller *roundPoller
	var telemetryHostFile string
	// process the wait parameters:
	for _, rule := range p.s.TerminationRules {
		switch rule.Class {
		case "Timeout":
			timeout = time.Duration(rule.TimeoutSec) * time.Second
		case "ReachRound":
			round = uint64(rule.Round)
			telemetryHostFile = filepath.Join(p.algonetDirectory, rule.TelemetryHostFile)
			rndPoller = makeRoundPoller(telemetryHostFile)
		case "RetestInterval":
			retestInterval = time.Duration(rule.RetestIntervalSec) * time.Second
		default:
			fmt.Printf("Termination Rule '%s' ignored, as this is unknown termination rule name\n", rule.Class)
		}
	}
	startTime := time.Now()
	for {
		if time.Since(startTime) > timeout {
			break
		}
		if round > 0 {
			if rndPoller != nil {
				currentRound, err := rndPoller.getRound()
				if err == nil && currentRound >= round {
					return
				}
				if verbose {
					if err != nil {
						fmt.Printf("Unable to query round number (%v); skipping round check.\n", err)
					} else {
						// no error, but we did not reached desired round number
						fmt.Printf("Round number %d reached. Waiting for round %d.\n", currentRound, round)
					}
				}
			}
		}
		time.Sleep(retestInterval)
	}
}

func (p *puppet) collectMetrics() {
	// process the metrics collection parameters:
	for _, metric := range p.s.MetricsCollection {
		switch metric.Class {
		case "Prometheus":
			telemetryHostFile := filepath.Join(p.algonetDirectory, metric.TelemetryHostFile)
			hostNameBytes, err := readHostFile(telemetryHostFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read '%s' : %v\n", telemetryHostFile, err)
			} else {
				metricFetcher := makePromMetricFetcher(string(hostNameBytes))
				results, err := metricFetcher.getMetric(metric.Query)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to read metric '%s' : %v\n", metric.Name, err)
					continue
				}
				result, err := metricFetcher.getSingleValue(results)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to parse metric '%s' : %v\n", metric.Name, err)
					continue
				}
				p.metrics[metric.Name] = result
			}
		default:
			if verbose {
				fmt.Printf("Metric collection class '%s' ignored, as this is unknown metric collection class\n", metric.Class)
			}
		}
	}
}
