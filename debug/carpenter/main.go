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

// carpenter builds meaningful patterns out of raw Algorand logs
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/algorand/go-algorand/logging/logspec"
)

var filename = flag.String("file", "", "Name of the input logfile (do not set to read from stdin)")
var dataDir = flag.String("d", "", "DataDirectory to track (do not set to read from stdin)")
var defaultDataDir = flag.Bool("D", false, "Track DataDirectory specified by $ALGORAND_DATA (do not set to read from stdin)")
var forceColor = flag.Bool("color", false, "Force sending color codes to output")
var forceNoColor = flag.Bool("no-color", false, "Disable sending color codes to output")
var cat = flag.Bool("cat", false, "Read input without using tail -F (option is ignored for stdin)")
var noLedger = flag.Bool("no-ledger", false, "Ignore log messages about the ledger")
var noAgree = flag.Bool("no-agree", false, "Ignore log messages about agreement")
var noDebug = flag.Bool("no-debug", false, "Ignore debug-level log messages")
var testing = flag.Bool("testing", false, "Set this if `file` was produced by a go test rather than a real node")
var verbose = flag.Bool("v", false, "Show why votes are rejected")
var tableFormat = flag.Bool("table", false, "Output in table format")
var tableWidth = flag.Int("width", 0, "Width of table output")

const defaultLogFilename = "node.log"

const (
	black   = color.FgBlack
	red     = color.FgRed
	green   = color.FgGreen
	yellow  = color.FgYellow
	blue    = color.FgBlue
	magenta = color.FgMagenta
	cyan    = color.FgCyan
	white   = color.FgWhite
)

// var colors = []color.Attribute{black, red, green, yellow, blue, magenta, cyan, white}
var colors = []color.Attribute{red, green, yellow, blue, magenta, cyan}

func errorf(s string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, s+"\n", a...)
	os.Exit(1)
}

func warnf(s string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, s+"\n", a...)
}

func colorize(s string) string {
	bytes := []byte(s)
	sum := 0
	for _, b := range bytes {
		sum += int(b)
	}
	i := sum % len(colors)

	return color.New(colors[i]).Sprint(s)
}

func bold(s string) string {
	return color.New(color.Bold).Sprint(s)
}

// Some fields get colorized or have other special formatting. The escape sequences added by colorize() mess up Printf's width formatting. So we implement fmt.Formatter ourselves. Now %v will nicely format these fields.
type hash string

func (h hash) Format(f fmt.State, c rune) {
	if c != 'v' {
		fmt.Fprint(f, string(h))
		return
	}
	width, ok := f.Width()
	if !ok {
		width = 5
	}
	truncated := strings.TrimPrefix(string(h), "blk-")
	truncated = strings.TrimPrefix(truncated, "addr-")
	truncated = fmt.Sprintf("%*.*s", width, width, truncated) // first truncate or pad to appropriate length...
	f.Write([]byte(colorize(truncated)))                      // ...*then* colorize; this way the color escape sequences don't count toward the length
}

type roundperiodstep struct {
	round  uint64
	period uint64
	step   uint64
}

func (rps roundperiodstep) Format(f fmt.State, c rune) {
	width, ok := f.Width()
	if !ok {
		width = 6
	}
	if rps.round == 0 {
		fmt.Fprintf(f, "%*s", width, " ")
		return
	}
	r := strconv.FormatUint(rps.round, 10)
	p := strconv.FormatUint(rps.period, 10)
	s := strconv.FormatUint(rps.step, 10)
	leadingspaces := ""
	if len(r)+len(p)+len(s)+2 < width {
		leadingspaces = fmt.Sprintf("%*s", width-len(r)-len(p)-len(s)-2, " ")
	}
	fmt.Fprintf(f, "%s%s.%s.%s", leadingspaces, colorize(r), colorize(p), colorize(s))
}

//
func setupInputStream() io.ReadCloser {
	var inputStream io.ReadCloser = os.Stdin

	if *filename == "" {
		// If filename not specified, see if a datadir was specified.
		if *defaultDataDir {
			*dataDir = os.ExpandEnv("$ALGORAND_DATA")
			if *dataDir == "" {
				errorf("$ALGORAND_DATA is not defined")
			}
		}

		if *dataDir != "" {
			*filename = filepath.Join(*dataDir, defaultLogFilename)
			fmt.Fprintf(os.Stdout, "Watching file: %s...\n", *filename)
		}
	}

	if *filename != "" {
		f, err := os.Open(*filename)
		if err != nil {
			errorf("cannot open file: %v", err)
		}
		if *cat {
			inputStream = f
		} else {
			// Close the handle - we just wanted to verify it was valid
			f.Close()

			cmd := exec.Command("tail", "-n", "-1000", "-F", *filename)
			var err error
			inputStream, err = cmd.StdoutPipe()
			if err != nil {
				errorf("cannot collect tail -F output of file: %v", err)
			}
			err = cmd.Start()
			if err != nil {
				errorf("cannot collect tail -F output of file: %v", err)
			}
		}
	}

	return inputStream
}

func filter(line string) bool {
	var obj map[string]interface{}
	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return false
	}

	dec := json.NewDecoder(strings.NewReader(line))
	err := dec.Decode(&obj)
	if err != nil {
		warnf("could not decode line from JSON: %s", line)
		return false
	}

	if _, ok := obj["Context"]; !ok {
		return false
	}

	level := obj["level"]
	if *noDebug && level == "debug" {
		return false
	}
	return true
}

func updateColumns(line string, columns []string, colPositions map[string]int) ([]string, map[string]int) {
	var event logspec.Event
	dec := json.NewDecoder(strings.NewReader(line))
	err := dec.Decode(&event)
	if err != nil {
		return columns, colPositions
	}

	source := event.Source
	if _, ok := colPositions[source]; !ok {
		colPositions[source] = len(columns)
		columns = append(columns, source)
	}
	return columns, colPositions
}

func showObject(line string, columns []string, colPositions map[string]int) error {
	var event logspec.Event
	dec := json.NewDecoder(strings.NewReader(line))
	err := dec.Decode(&event)
	if err != nil {
		return err
	}

	var out string
	switch event.Context {
	case logspec.Agreement:
		// fmt.Printf("%v\n", line)
		if *noAgree {
			return nil
		}
		out, err = showAgreement(line)
	case logspec.Ledger:
		if *noLedger {
			return nil
		}
		out, err = showLedger(line)
	default:
		return errors.New("could not identify object context")
	}

	if err != nil {
		return err
	}

	if *tableFormat {
		outputTableFormat(out, event, columns, colPositions)
	} else {
		outputNormal(out, event, columns, colPositions)
	}

	return err
}

func outputNormal(out string, event logspec.Event, columns []string, colPositions map[string]int) {
	cellFormat := "%52s|"
	i := 0
	for ; i < colPositions[event.Source]; i++ {
		fmt.Printf(cellFormat, " ")
	}
	fmt.Printf(cellFormat, out)
	i++
	for ; i < len(colPositions); i++ {
		fmt.Printf(cellFormat, " ")
	}
	fmt.Println()
}

func outputTableFormat(out string, event logspec.Event, columns []string, colPositions map[string]int) {

	terminalWidth, _, err := terminal.GetSize(0)
	if err != nil {
		terminalWidth = 200
	}
	if *tableWidth > 0 {
		terminalWidth = *tableWidth
	}

	// remove tabs and standardize spaces
	out = strings.Replace(out, "\t", "", -1)
	out = strings.Join(strings.Fields(out), " ")

	columnCount := len(columns)
	columnWidth := (terminalWidth / columnCount) - 1
	rowCount := len(out)/columnWidth + 1

	headerTabWriter := tabwriter.NewWriter(os.Stdout, columnWidth, 0, 0, '-', tabwriter.Debug)
	bodyTabWriter := tabwriter.NewWriter(os.Stdout, columnWidth, 0, 0, ' ', tabwriter.Debug)
	sort.Strings(columns)
	columnHeaders := ""
	for i := 0; i < columnCount; i++ {
		columnHeaders = fmt.Sprintf("%s%s\t", columnHeaders, columns[i])
	}

	outputRow(headerTabWriter, columnHeaders)

	maxLen := len(out)
	for i := 0; i < rowCount; i++ {
		start := i * columnWidth
		end := start + columnWidth
		if end > maxLen {
			end = maxLen
		}
		if start < len(out) {
			row := strings.TrimSpace(out[start:end])
			output := ""
			for j := 0; j < len(columns); j++ {
				if colPositions[event.Source] == j {
					output = fmt.Sprintf("%s%s", output, row)
				}
				output = fmt.Sprintf("%s\t", output)
			}
			outputRow(bodyTabWriter, output)
		}
	}

	return
}

func outputRow(tabWriter *tabwriter.Writer, rowContent string) {

	//fmt.Printf("rowContent: '%s'\n\n", strings.Replace(rowContent, "\t", "^", -1))
	fmt.Fprintln(tabWriter, rowContent)
	tabWriter.Flush()
}

type agreementLogMessage struct {
	logspec.AgreementEvent
	Message string `json:"msg"`
}

func showAgreement(line string) (string, error) {
	var event agreementLogMessage

	dec := json.NewDecoder(strings.NewReader(line))
	err := dec.Decode(&event)
	if err != nil {
		return "", err
	}

	eventType := event.Type.String()
	if event.Type == logspec.VoteAccepted || event.Type == logspec.ThresholdReached {
		eventType = fmt.Sprintf("%s(%d/%d)", event.Type, event.Weight, event.WeightTotal)
	}

	eventHash := hash(event.Hash)
	rps := roundperiodstep{event.Round, event.Period, event.Step}
	objrps := roundperiodstep{event.ObjectRound, event.ObjectPeriod, event.ObjectStep}
	cell := fmt.Sprintf("%7v:%30.30s %5v-%7v", rps, eventType, eventHash, objrps)
	if strings.Contains(eventType, "Conclude") {
		cell = fmt.Sprintf("%v:%38.38s %v-%v", rps, bold(eventType), eventHash, objrps)
		if strings.Contains(eventType, "Round") {
			cell += " "
		}
	}
	if *verbose && event.Type == logspec.VoteRejected {
		cell = fmt.Sprintf("%s %s", cell, event.Message)
	}
	return cell, nil
}

func showLedger(line string) (string, error) {
	var event logspec.LedgerEvent

	dec := json.NewDecoder(strings.NewReader(line))
	err := dec.Decode(&event)
	if err != nil {
		return "", err
	}
	switch event.Type {
	case logspec.WroteBlock:
		return bold(fmt.Sprintf("%v:Wrote block:%v (%d txns)     ", roundperiodstep{event.Round, 0, 0}, hash(event.Hash), event.TxnCount)), nil
	default:
		return "", errors.New("unknown ledger event type")
	}
}

func main() {
	flag.Parse()

	// The "color" package auto disables colors if output is not to a terminal, but we allow overriding this
	if *forceColor {
		color.NoColor = false
	}
	if *forceNoColor || *tableFormat {
		color.NoColor = true
	}

	inputStream := setupInputStream()

	columns := make([]string, 0)
	colPositions := make(map[string]int)
	// accPositions

	scanner := bufio.NewScanner(inputStream)
	for scanner.Scan() {
		line := scanner.Text()
		if !filter(line) {
			continue
		}

		columns, colPositions = updateColumns(line, columns, colPositions)

		err := showObject(line, columns, colPositions)
		if err != nil {
			continue
		}
	}
}
