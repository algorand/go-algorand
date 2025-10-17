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
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/zstd"
	"github.com/algorand/go-algorand/network/vpack"
	"github.com/algorand/go-algorand/protocol"
	kzstd "github.com/klauspost/compress/zstd"
	"github.com/valyala/gozstd"
)

// testCorpus holds all the test data loaded from message files
type testCorpus struct {
	messages []StoredMessage
	total    int64
}

// Global cache for test corpus
var cachedCorpus *testCorpus

func TestPrintTestCorpus(t *testing.T) {
	corpus := loadTestCorpus(t)
	t.Logf("Loaded %d messages (%d bytes)", len(corpus.messages), corpus.total)
	cnt := 0
	var origBytes, compBytes int64
	enc := vpack.NewStatelessEncoder()
	dec := vpack.NewStatelessDecoder()
	for i, msg := range corpus.messages {
		if msg.Tag != "AV" {
			continue
		}
		cnt++
		encBytes, err := enc.CompressVote(nil, msg.Data)
		if err != nil {
			t.Logf("parseVoteMsgpack: %v", err)
		}
		decBytes, err := dec.DecompressVote(nil, encBytes)
		if err != nil {
			t.Fatalf("DecompressSimple: %v", err)
		}
		if !bytes.Equal(decBytes, msg.Data) {
			t.Logf("msgbuf: %s", hex.EncodeToString(decBytes))
			t.Logf("msgDat: %s", hex.EncodeToString(msg.Data))
			b64data := base64.StdEncoding.EncodeToString(msg.Data)
			t.Logf("Message %d len %d: tag %s: %s", i, len(msg.Data), msg.Tag, b64data)
			t.Fatalf("Message %d: mismatch: %d vs %d bytes", i, len(encBytes), len(msg.Data))
		}
		origBytes += int64(len(msg.Data))
		compBytes += int64(len(encBytes))
	}
	t.Logf("Processed %d messages", cnt)
	t.Logf("Total bytes: %d, compressed: %d, ratio: %0.4f", origBytes, compBytes, (1.0 - float64(compBytes)/float64(origBytes)))
}

// filterMessages returns a slice of messages filtered by criteria.
// If onlyAV is true, only messages with Tag "AV" will be included.
// The function will also check if the filtered list is empty and call b.Fatal if it is.
func filterMessages(b *testing.B, corpus *testCorpus, onlyAV bool) []StoredMessage {
	var filtered []StoredMessage
	for _, msg := range corpus.messages {
		// Filter by tag if needed
		if onlyAV && msg.Tag != "AV" {
			continue
		}

		filtered = append(filtered, msg)
	}

	// Report an error if no messages pass the filter
	if len(filtered) == 0 {
		b.Fatal("No messages to benchmark")
	}

	return filtered
}

type filterOption struct {
	name   string
	onlyAV bool
}

var defaultFilterOptions = []filterOption{
	{name: "all", onlyAV: false},
	{name: "av", onlyAV: true},
}

func parseFilterOptions(keys []string) []filterOption {
	for _, key := range keys {
		if key == "" {
			continue
		}
		val := strings.TrimSpace(os.Getenv(key))
		if val == "" {
			continue
		}
		var opts []filterOption
		seen := make(map[string]struct{})
		for _, part := range strings.Split(val, ",") {
			switch strings.ToLower(strings.TrimSpace(part)) {
			case "all":
				if _, ok := seen["all"]; !ok {
					opts = append(opts, filterOption{name: "all", onlyAV: false})
					seen["all"] = struct{}{}
				}
			case "av", "onlyav", "votes":
				if _, ok := seen["av"]; !ok {
					opts = append(opts, filterOption{name: "av", onlyAV: true})
					seen["av"] = struct{}{}
				}
			}
		}
		if len(opts) > 0 {
			return opts
		}
	}
	return defaultFilterOptions
}

func parseIntListFromEnv(keys []string, defaults []int) []int {
	for _, key := range keys {
		if key == "" {
			continue
		}
		val := strings.TrimSpace(os.Getenv(key))
		if val == "" {
			continue
		}
		var parsed []int
		seen := make(map[int]struct{})
		for _, part := range strings.Split(val, ",") {
			numStr := strings.TrimSpace(part)
			if numStr == "" {
				continue
			}
			num, err := strconv.Atoi(numStr)
			if err != nil {
				continue
			}
			if _, ok := seen[num]; ok {
				continue
			}
			seen[num] = struct{}{}
			parsed = append(parsed, num)
		}
		if len(parsed) > 0 {
			return parsed
		}
	}
	return defaults
}

type simpleCompressor func(dst, src []byte) ([]byte, error)

type simpleCompressorBuilder func(level int) (simpleCompressor, func(), error)

func runSimpleCompressionMatrix(b *testing.B, benchName string, corpus *testCorpus, levels []int, filters []filterOption, build simpleCompressorBuilder) {
	for _, opt := range filters {
		filtered := filterMessages(b, corpus, opt.onlyAV)
		for _, level := range levels {
			opt := opt
			b.Run(fmt.Sprintf("%s/level=%d/%s", benchName, level, opt.name), func(b *testing.B) {
				compress, cleanup, err := build(level)
				if err != nil {
					b.Fatalf("setup failed: %v", err)
				}
				if cleanup != nil {
					defer cleanup()
				}
				runCompressionLoop(b, filtered, compress)
			})
		}
	}
}

func runCompressionLoop(b *testing.B, msgs []StoredMessage, compress simpleCompressor) {
	if len(msgs) == 0 {
		b.Fatal("no messages to benchmark")
	}
	compressed := make([]byte, 0, 4096)
	var totalCompressed int64
	var origBytes int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg := msgs[i%len(msgs)]
		var err error
		compressed, err = compress(compressed[:0], msg.Data)
		if err != nil {
			b.Fatalf("compression failed: %v", err)
		}
		totalCompressed += int64(len(compressed))
		origBytes += int64(len(msg.Data))
	}
	b.StopTimer()
	if totalCompressed == 0 {
		b.Fatalf("compression produced zero bytes")
	}
	if b.N > 0 {
		perIteration := origBytes / int64(b.N)
		b.SetBytes(perIteration)
	}
	ratio := float64(origBytes) / float64(totalCompressed)
	reduction := 100 - float64(totalCompressed)/float64(origBytes)*100
	b.ReportMetric(ratio, "ratio")
	b.ReportMetric(reduction, "%smaller")
}

type simpleDecompressor func(dst, src []byte) ([]byte, error)

type decompressionSetup func(level int, msgs []StoredMessage) ([][]byte, simpleDecompressor, func(), error)

func runSimpleDecompressionMatrix(b *testing.B, benchName string, corpus *testCorpus, levels []int, filters []filterOption, setup decompressionSetup) {
	for _, opt := range filters {
		filtered := filterMessages(b, corpus, opt.onlyAV)
		for _, level := range levels {
			opt := opt
			b.Run(fmt.Sprintf("%s/level=%d/%s", benchName, level, opt.name), func(b *testing.B) {
				compressed, decompress, cleanup, err := setup(level, filtered)
				if err != nil {
					b.Fatalf("setup failed: %v", err)
				}
				if cleanup != nil {
					defer cleanup()
				}
				runDecompressionLoop(b, compressed, decompress)
			})
		}
	}
}

func runDecompressionLoop(b *testing.B, compressed [][]byte, decompress simpleDecompressor) {
	if len(compressed) == 0 {
		b.Fatal("no compressed data to benchmark")
	}
	decompressed := make([]byte, 0, 4096)
	var totalCompressed int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		block := compressed[i%len(compressed)]
		var err error
		decompressed, err = decompress(decompressed[:0], block)
		if err != nil {
			b.Fatalf("decompression failed: %v", err)
		}
		totalCompressed += int64(len(block))
	}
	b.StopTimer()
	if b.N > 0 {
		b.SetBytes(totalCompressed / int64(b.N))
	}
}

type levelWindowLog struct {
	level     int
	windowLog int
}

func parseLevelWindowLogList(keys []string, defaults []levelWindowLog) []levelWindowLog {
	for _, key := range keys {
		if key == "" {
			continue
		}
		val := strings.TrimSpace(os.Getenv(key))
		if val == "" {
			continue
		}
		var result []levelWindowLog
		seen := make(map[levelWindowLog]struct{})
		for _, part := range strings.Split(val, ",") {
			fields := strings.Split(part, ":")
			if len(fields) != 2 {
				continue
			}
			level, err1 := strconv.Atoi(strings.TrimSpace(fields[0]))
			windowLog, err2 := strconv.Atoi(strings.TrimSpace(fields[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			cfg := levelWindowLog{level: level, windowLog: windowLog}
			if _, ok := seen[cfg]; ok {
				continue
			}
			seen[cfg] = struct{}{}
			result = append(result, cfg)
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaults
}

type levelWindow struct {
	level  int
	window int
}

func parseLevelWindowList(keys []string, defaults []levelWindow) []levelWindow {
	for _, key := range keys {
		if key == "" {
			continue
		}
		val := strings.TrimSpace(os.Getenv(key))
		if val == "" {
			continue
		}
		var result []levelWindow
		seen := make(map[levelWindow]struct{})
		for _, part := range strings.Split(val, ",") {
			fields := strings.Split(part, ":")
			if len(fields) != 2 {
				continue
			}
			level, err1 := strconv.Atoi(strings.TrimSpace(fields[0]))
			window, err2 := strconv.Atoi(strings.TrimSpace(fields[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			cfg := levelWindow{level: level, window: window}
			if _, ok := seen[cfg]; ok {
				continue
			}
			seen[cfg] = struct{}{}
			result = append(result, cfg)
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaults
}

type tagWindowConfig struct {
	level      int
	avWindow   int
	txppWindow int
}

func parseTagWindowConfigs(keys []string, defaults []tagWindowConfig) []tagWindowConfig {
	for _, key := range keys {
		if key == "" {
			continue
		}
		val := strings.TrimSpace(os.Getenv(key))
		if val == "" {
			continue
		}
		var result []tagWindowConfig
		seen := make(map[tagWindowConfig]struct{})
		for _, part := range strings.Split(val, ",") {
			fields := strings.Split(part, ":")
			if len(fields) != 3 {
				continue
			}
			level, err1 := strconv.Atoi(strings.TrimSpace(fields[0]))
			avWindow, err2 := strconv.Atoi(strings.TrimSpace(fields[1]))
			txppWindow, err3 := strconv.Atoi(strings.TrimSpace(fields[2]))
			if err1 != nil || err2 != nil || err3 != nil {
				continue
			}
			cfg := tagWindowConfig{level: level, avWindow: avWindow, txppWindow: txppWindow}
			if _, ok := seen[cfg]; ok {
				continue
			}
			seen[cfg] = struct{}{}
			result = append(result, cfg)
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaults
}

var (
	defaultGozstdLevels    = []int{1, 3, 7, 11}
	defaultZstdLevels      = []int{1, 3, 7, 11}
	defaultKlauspostLevels = []int{1, 3}
	defaultGozstdWindowLog = []levelWindowLog{
		{level: 1, windowLog: 15},
		{level: 1, windowLog: 18},
		{level: 1, windowLog: 20},
		{level: 3, windowLog: 15},
		{level: 3, windowLog: 18},
		{level: 3, windowLog: 20},
		{level: 7, windowLog: 18},
		{level: 11, windowLog: 18},
	}
	defaultKlauspostWindows = []levelWindow{
		{level: 1, window: 1 << 12},
		{level: 1, window: 1 << 15},
		{level: 1, window: 1 << 16},
		{level: 1, window: 1 << 18},
		{level: 1, window: 1 << 20},
		{level: 2, window: 1 << 15},
		{level: 2, window: 1 << 18},
		{level: 2, window: 1 << 20},
		{level: 3, window: 1 << 18},
		{level: 3, window: 1 << 20},
	}
	defaultKlauspostStreamConfigs = []levelWindow{
		{level: 1, window: 1 << 12},
		{level: 1, window: 1 << 15},
		{level: 1, window: 1 << 18},
		{level: 1, window: 1 << 20},
		{level: 2, window: 1 << 15},
		{level: 2, window: 1 << 18},
		{level: 2, window: 1 << 20},
		{level: 3, window: 1 << 18},
		{level: 3, window: 1 << 20},
	}
	defaultTagContextConfigs = []tagWindowConfig{
		{level: 1, avWindow: 1 << 18, txppWindow: 1 << 15},
		{level: 1, avWindow: 1 << 17, txppWindow: 1 << 15},
		{level: 2, avWindow: 1 << 18, txppWindow: 1 << 15},
		{level: 3, avWindow: 1 << 18, txppWindow: 1 << 15},
	}
)

func loadTestCorpus(t testing.TB) *testCorpus {
	// If we already have a cached corpus, return it without reloading
	if cachedCorpus != nil {
		return cachedCorpus
	}

	// Default directories to scan
	directories := []string{"./messages"}

	// If environment variable is set, use it to override defaults
	if customDirsSetting := os.Getenv("ALGODUMP_TEST_MESSAGES"); customDirsSetting != "" {
		directories = strings.Split(customDirsSetting, ",")
	}

	var corpus testCorpus
	var totalFiles int
	var dirCounts = make(map[string]int)
	// Track messages per tag
	tagCounts := make(map[protocol.Tag]int)

	// Process each directory
	for _, dir := range directories {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Just log an error and continue with other directories
			t.Logf("Warning: failed to read directory %s: %v", dir, err)
			continue
		}

		dirMessageCount := 0
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasPrefix(entry.Name(), "messages-") {
				path := filepath.Join(dir, entry.Name())
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("failed to read test data: %v", err)
				}
				var messages []StoredMessage
				err = protocol.DecodeReflect(data, &messages)
				if err != nil {
					t.Fatalf("failed to decode test data: %v", err)
				}

				// Count messages from this file
				dirMessageCount += len(messages)
				totalFiles++

				// Calculate total bytes and count by tag
				for _, msg := range messages {
					corpus.total += int64(len(msg.Data))
					tagCounts[msg.Tag]++
				}

				// Add messages to corpus
				corpus.messages = append(corpus.messages, messages...)
			}
		}

		// Store count of messages from this directory
		dirCounts[dir] = dirMessageCount
	}

	// Print loading statistics (only happens once since we cache the corpus)
	// Only print if verbose mode is enabled via GO_TEST_VERBOSE=1
	if vFlag := flag.Lookup("test.v"); vFlag != nil && vFlag.Value.String() == "true" {
		t.Logf("Loaded %d messages (%.2f MB) from %d files across %d directories:",
			len(corpus.messages),
			float64(corpus.total)/1024/1024,
			totalFiles,
			len(dirCounts))

		// Print per-directory counts
		for dir, count := range dirCounts {
			if count > 0 {
				t.Logf("  - %s: %d messages", dir, count)
			}
		}

		// Print message counts by tag
		t.Log("Messages by tag:")

		for _, tagStr := range slices.Sorted(maps.Keys(tagCounts)) {
			tag := protocol.Tag(tagStr)
			t.Logf("  - %s: %d messages", tagStr, tagCounts[tag])
		}
	}

	if len(corpus.messages) == 0 {
		t.Skip("no message files found in any test directory")
	}

	// Cache the corpus for future calls
	cachedCorpus = &corpus
	return cachedCorpus
}

// BenchmarkVPackCompression benchmarks stateless vpack compression
func BenchmarkVPackCompression(b *testing.B) {
	corpus := loadTestCorpus(b)

	// Filter messages to only include AV votes
	filtered := filterMessages(b, corpus, true)

	enc := vpack.NewStatelessEncoder()
	compressed := make([]byte, 0, 4096)

	b.ResetTimer()
	var totalCompressed int64
	var origBytes int64
	for i := 0; i < b.N; i++ {
		// Process one message per iteration, cycling through messages
		msg := filtered[i%len(filtered)]

		var err error
		compressed, err = enc.CompressVote(compressed, msg.Data)
		if err != nil {
			b.Fatalf("CompressVote failed: %v", err)
		}
		totalCompressed += int64(len(compressed))
		origBytes += int64(len(msg.Data))
	}
	b.StopTimer()

	b.ReportMetric(float64(origBytes)/float64(totalCompressed), "ratio")
	b.ReportMetric(100-float64(totalCompressed)/float64(origBytes)*100, "%smaller")
	b.SetBytes(origBytes / int64(b.N))
}

// BenchmarkVPackDecompression benchmarks stateless vpack decompression
func BenchmarkVPackDecompression(b *testing.B) {
	corpus := loadTestCorpus(b)

	// First compress all AV messages to have compressed data for benchmark
	filtered := filterMessages(b, corpus, true)
	compressedData := make([][]byte, 0, len(filtered))
	var totalDecompressed int64

	enc := vpack.NewStatelessEncoder()

	// Pre-compress the messages
	for _, msg := range filtered {
		encBytes, err := enc.CompressVote(nil, msg.Data)
		if err != nil {
			b.Fatalf("CompressVote failed during setup: %v", err)
		}
		compressedData = append(compressedData, encBytes)
	}

	if len(compressedData) == 0 {
		b.Fatal("No compressed data to benchmark")
	}

	b.ResetTimer()
	decompressed := make([]byte, 0, 1024)
	dec := vpack.NewStatelessDecoder()
	for i := 0; i < b.N; i++ {
		// Process one compressed message per iteration, cycling through compressedData
		compressed := compressedData[i%len(compressedData)]

		decompressed, err := dec.DecompressVote(decompressed[:0], compressed)
		if err != nil {
			b.Fatalf("DecompressSimple failed: %v", err)
		}
		totalDecompressed += int64(len(decompressed))
	}
	b.StopTimer()

	b.SetBytes(totalDecompressed / int64(b.N))
}

// benchmarkGozstdWindow benchmarks the valyala/gozstd implementation
// with a specific window size (using WriterParams)
func benchmarkGozstdWindow(b *testing.B, level int, windowLog int) {
	corpus := loadTestCorpus(b)

	filtered := filterMessages(b, corpus, false)

	// Create parameters with the specified window size
	params := &gozstd.WriterParams{
		CompressionLevel: level,
		WindowLog:        windowLog,
	}

	// Create a buffer to hold the compressed data that will be reused
	var buf bytes.Buffer

	// Create a writer with our window size parameters that will be reused
	zw := gozstd.NewWriterParams(&buf, params)
	defer zw.Release()

	compress := func(dst, src []byte) ([]byte, error) {
		buf.Reset()
		if _, err := zw.Write(src); err != nil {
			return nil, err
		}
		if err := zw.Flush(); err != nil {
			return nil, err
		}
		return append(dst[:0], buf.Bytes()...), nil
	}
	runCompressionLoop(b, filtered, compress)
}

// benchmarkKlauspostWindow benchmarks the Klauspost zstd implementation
// with specific window size (one encoder for all messages, resetting window after each)
func benchmarkKlauspostWindow(b *testing.B, level int, windowSize int) {
	corpus := loadTestCorpus(b)

	filtered := filterMessages(b, corpus, false)

	enc, err := kzstd.NewWriter(nil, kzstd.WithEncoderLevel(kzstd.EncoderLevel(level)),
		kzstd.WithWindowSize(windowSize))
	if err != nil {
		b.Fatal(err)
	}
	defer enc.Close()

	compress := func(dst, src []byte) ([]byte, error) {
		return enc.EncodeAll(src, dst[:0]), nil
	}
	runCompressionLoop(b, filtered, compress)
}

// benchmarkKlauspostStream benchmarks the Klauspost zstd implementation
// with a streaming approach (accumulating context across messages)
func benchmarkKlauspostStream(b *testing.B, level int, windowSize int) {
	corpus := loadTestCorpus(b)

	filtered := filterMessages(b, corpus, false)

	var buf bytes.Buffer
	enc, err := kzstd.NewWriter(&buf,
		kzstd.WithEncoderLevel(kzstd.EncoderLevel(level)),
		kzstd.WithWindowSize(windowSize))
	if err != nil {
		b.Fatal(err)
	}
	defer enc.Close()

	compress := func(dst, src []byte) ([]byte, error) {
		buf.Reset()
		if _, err := enc.Write(src); err != nil {
			return nil, err
		}
		if err := enc.Flush(); err != nil {
			return nil, err
		}
		return append(dst[:0], buf.Bytes()...), nil
	}
	runCompressionLoop(b, filtered, compress)
}

// benchmarkTagSpecificContexts benchmarks a simulated algodump scenario with different
// window sizes for different message types, mimicking the tag-specific contexts
func benchmarkTagSpecificContexts(b *testing.B, level int, avWindow, txppWindow int) {
	corpus := loadTestCorpus(b)

	// Get a list of all the messages we need to process - we need both AV and TX/PP
	// We'll categorize them later rather than filtering here
	if len(corpus.messages) == 0 {
		b.Fatal("No messages to benchmark")
	}

	// Create a reproducible sequence of messages to process
	// Group messages by type so we can process them in a deterministic pattern
	var avMessages []StoredMessage
	var txppMessages []StoredMessage

	for _, msg := range corpus.messages {
		if msg.Tag == "AV" {
			avMessages = append(avMessages, msg)
		} else if msg.Tag == "TX" || msg.Tag == "PP" {
			txppMessages = append(txppMessages, msg)
		}
	}

	if len(avMessages) == 0 {
		b.Fatal("No AV messages to benchmark")
	}

	if len(txppMessages) == 0 {
		b.Fatal("No TX/PP messages to benchmark")
	}

	// For real-world simulation, we want to process a mix of messages in each benchmark iteration
	// Let's use a fixed number of each message type per iteration
	messagesPerType := 5 // Process 5 of each type per iteration
	if len(avMessages) < messagesPerType {
		messagesPerType = len(avMessages)
	}
	if len(txppMessages) < messagesPerType {
		messagesPerType = len(txppMessages)
	}

	// Setup encoders for the different tag groups
	avEnc, _ := kzstd.NewWriter(nil,
		kzstd.WithEncoderLevel(kzstd.EncoderLevel(level)),
		kzstd.WithWindowSize(avWindow))
	defer avEnc.Close()

	txppEnc, _ := kzstd.NewWriter(nil,
		kzstd.WithEncoderLevel(kzstd.EncoderLevel(level)),
		kzstd.WithWindowSize(txppWindow))
	defer txppEnc.Close()

	// Pre-allocate a buffer that we'll reuse
	compressed := make([]byte, 0, 4096)

	b.ResetTimer()
	var totalCompressed int64
	var origBytes int64
	for i := 0; i < b.N; i++ {
		// Process a fixed number of each message type with the appropriate encoder
		// Starting from positions based on the iteration (i)
		avBaseIdx := (i * messagesPerType) % len(avMessages)
		txppBaseIdx := (i * messagesPerType) % len(txppMessages)

		// Process AV messages
		for j := 0; j < messagesPerType; j++ {
			msgIdx := (avBaseIdx + j) % len(avMessages)
			msg := avMessages[msgIdx]

			compressed = avEnc.EncodeAll(msg.Data, compressed[:0])
			totalCompressed += int64(len(compressed))
			origBytes += int64(len(msg.Data))
		}

		// Process TX/PP messages
		for j := 0; j < messagesPerType; j++ {
			msgIdx := (txppBaseIdx + j) % len(txppMessages)
			msg := txppMessages[msgIdx]

			compressed = txppEnc.EncodeAll(msg.Data, compressed[:0])
			totalCompressed += int64(len(compressed))
			origBytes += int64(len(msg.Data))
		}
	}
	b.StopTimer()

	b.ReportMetric(float64(origBytes)/float64(totalCompressed), "ratio")
	b.ReportMetric(100-float64(totalCompressed)/float64(origBytes)*100, "%smaller")
	b.SetBytes(origBytes / int64(b.N)) // For MB/s calculation, use per-iteration bytes
}

// BenchmarkVPackDynamicCompression benchmarks the stateful vpack compression implementation
// This uses the two-layer compression: StatelessEncoder → StatefulEncoder
func BenchmarkVPackDynamicCompression(b *testing.B) {
	corpus := loadTestCorpus(b)

	// Filter messages to only include AV votes
	filtered := filterMessages(b, corpus, true)

	b.Logf("Number of messages: %d", len(filtered))

	// Create both encoder types - stateless for first layer, stateful for second
	stEnc := vpack.NewStatelessEncoder()
	dynEnc, err := vpack.NewStatefulEncoder(1024)
	if err != nil {
		b.Fatalf("Failed to create StatefulEncoder: %v", err)
	}

	// Buffers for intermediate and final compression results
	statelessBuf := make([]byte, 0, 4096)
	compressed := make([]byte, 0, 4096)

	// For measuring stateless vs. stateful sizes
	var statelessTotalSize, statefulTotalSize int64

	b.ResetTimer()
	var totalCompressed int64
	var origBytes int64
	for i := 0; i < b.N; i++ {
		// Process one message per iteration, cycling through messages
		msg := filtered[i%len(filtered)]

		// First layer: stateless compression
		var err error
		statelessBuf, err = stEnc.CompressVote(statelessBuf[:0], msg.Data)
		if err != nil {
			b.Fatalf("StatelessEncoder failed: %v", err)
		}

		// Track total stateless size
		statelessTotalSize += int64(len(statelessBuf))

		// Second layer: stateful compression
		compressed, err = dynEnc.Compress(compressed[:0], statelessBuf)
		if err != nil {
			b.Fatalf("StatefulEncoder failed: %v", err)
		}

		// Track total stateful size
		statefulTotalSize += int64(len(compressed))

		totalCompressed += int64(len(compressed))
		origBytes += int64(len(msg.Data))
	}
	b.StopTimer()

	// Report compression ratio and other metrics
	b.ReportMetric(float64(origBytes)/float64(totalCompressed), "ratio")
	b.ReportMetric(100-float64(totalCompressed)/float64(origBytes)*100, "%smaller")
	b.SetBytes(origBytes / int64(b.N))

	if statelessTotalSize > 0 && statefulTotalSize > 0 {
		b.Logf("Stateless size: %d bytes, Stateful size: %d bytes",
			statelessTotalSize, statefulTotalSize)
		b.Logf("Additional compression ratio: %.2fx",
			float64(statelessTotalSize)/float64(statefulTotalSize))
		b.Logf("Additional space reduction: %.2f%%",
			(1.0-float64(statefulTotalSize)/float64(statelessTotalSize))*100)
	}
}

// BenchmarkVPackDynamicDecompression benchmarks the stateful vpack decompression implementation
// This uses the two-layer decompression: StatefulDecoder → StatelessDecoder
func BenchmarkVPackDynamicDecompression(b *testing.B) {
	corpus := loadTestCorpus(b)

	// First compress all AV messages to have compressed data for benchmark
	filtered := filterMessages(b, corpus, true)
	compressedData := make([][]byte, 0, len(filtered))

	// Create both encoder types for pre-compression
	stEnc := vpack.NewStatelessEncoder()
	dynEnc, err := vpack.NewStatefulEncoder(1024)
	if err != nil {
		b.Fatalf("Failed to create StatefulEncoder: %v", err)
	}

	// Pre-compress the messages through both layers
	for _, msg := range filtered {
		// First layer: stateless
		stBuf, err := stEnc.CompressVote(nil, msg.Data)
		if err != nil {
			b.Fatalf("StatelessEncoder failed during setup: %v", err)
		}

		// Second layer: stateful
		encBytes, err := dynEnc.Compress(nil, stBuf)
		if err != nil {
			b.Fatalf("StatefulEncoder failed during setup: %v", err)
		}

		compressedData = append(compressedData, encBytes)
	}

	if len(compressedData) == 0 {
		b.Fatal("No compressed data to benchmark")
	}

	b.ResetTimer()
	var totalDecompressed int64

	// Create both decoder types for benchmark
	dynDec, err := vpack.NewStatefulDecoder(1024)
	if err != nil {
		b.Fatalf("Failed to create StatefulDecoder: %v", err)
	}
	stDec := vpack.NewStatelessDecoder()

	// Intermediate and final buffers
	statelessBuf := make([]byte, 0, 1024)
	decompressed := make([]byte, 0, 1024)

	for i := 0; i < b.N; i++ {
		// Process one compressed message per iteration, cycling through compressedData
		compressed := compressedData[i%len(compressedData)]

		// First layer: stateful decompression
		var err error
		statelessBuf, err = dynDec.Decompress(statelessBuf[:0], compressed)
		if err != nil {
			b.Fatalf("StatefulDecoder failed: %v", err)
		}

		// Second layer: stateless decompression
		decompressed, err = stDec.DecompressVote(decompressed[:0], statelessBuf)
		if err != nil {
			b.Fatalf("StatelessDecoder failed: %v", err)
		}

		totalDecompressed += int64(len(decompressed))
	}
	b.StopTimer()

	b.SetBytes(totalDecompressed / int64(b.N))
}

func BenchmarkGozstdSimple(b *testing.B) {
	corpus := loadTestCorpus(b)
	levels := parseIntListFromEnv([]string{"ALGODUMP_GOZSTD_LEVELS", "ALGODUMP_BENCH_LEVELS"}, defaultGozstdLevels)
	filters := parseFilterOptions([]string{"ALGODUMP_GOZSTD_FILTERS", "ALGODUMP_BENCH_FILTERS"})
	runSimpleCompressionMatrix(b, "gozstd/simple", corpus, levels, filters, func(level int) (simpleCompressor, func(), error) {
		return func(dst, src []byte) ([]byte, error) {
			return gozstd.CompressLevel(dst[:0], src, level), nil
		}, nil, nil
	})
}

func BenchmarkZstdSimple(b *testing.B) {
	corpus := loadTestCorpus(b)
	levels := parseIntListFromEnv([]string{"ALGODUMP_ZSTD_LEVELS", "ALGODUMP_BENCH_LEVELS"}, defaultZstdLevels)
	filters := parseFilterOptions([]string{"ALGODUMP_ZSTD_FILTERS", "ALGODUMP_BENCH_FILTERS"})
	runSimpleCompressionMatrix(b, "zstd/simple", corpus, levels, filters, func(level int) (simpleCompressor, func(), error) {
		return func(dst, src []byte) ([]byte, error) {
			return zstd.CompressLevel(dst[:0], src, level)
		}, nil, nil
	})
}

func BenchmarkKlauspostSimple(b *testing.B) {
	corpus := loadTestCorpus(b)
	levels := parseIntListFromEnv([]string{"ALGODUMP_KLAUSPOST_LEVELS", "ALGODUMP_BENCH_LEVELS"}, defaultKlauspostLevels)
	filters := parseFilterOptions([]string{"ALGODUMP_KLAUSPOST_FILTERS", "ALGODUMP_BENCH_FILTERS"})
	runSimpleCompressionMatrix(b, "klauspost/simple", corpus, levels, filters, func(level int) (simpleCompressor, func(), error) {
		enc, err := kzstd.NewWriter(nil, kzstd.WithEncoderLevel(kzstd.EncoderLevel(level)))
		if err != nil {
			return nil, nil, err
		}
		compress := func(dst, src []byte) ([]byte, error) {
			return enc.EncodeAll(src, dst[:0]), nil
		}
		cleanup := func() { enc.Close() }
		return compress, cleanup, nil
	})
}

func BenchmarkGozstdDecompress(b *testing.B) {
	corpus := loadTestCorpus(b)
	levels := parseIntListFromEnv([]string{"ALGODUMP_GOZSTD_LEVELS", "ALGODUMP_BENCH_LEVELS"}, defaultGozstdLevels)
	filters := parseFilterOptions([]string{"ALGODUMP_GOZSTD_FILTERS", "ALGODUMP_BENCH_FILTERS"})
	runSimpleDecompressionMatrix(b, "gozstd/decompress", corpus, levels, filters, func(level int, msgs []StoredMessage) ([][]byte, simpleDecompressor, func(), error) {
		compressed := make([][]byte, len(msgs))
		for i, msg := range msgs {
			compressed[i] = gozstd.CompressLevel(nil, msg.Data, level)
		}
		decompress := func(dst, src []byte) ([]byte, error) {
			return gozstd.Decompress(dst[:0], src)
		}
		return compressed, decompress, nil, nil
	})
}

func BenchmarkZstdDecompress(b *testing.B) {
	corpus := loadTestCorpus(b)
	levels := parseIntListFromEnv([]string{"ALGODUMP_ZSTD_LEVELS", "ALGODUMP_BENCH_LEVELS"}, defaultZstdLevels)
	filters := parseFilterOptions([]string{"ALGODUMP_ZSTD_FILTERS", "ALGODUMP_BENCH_FILTERS"})
	runSimpleDecompressionMatrix(b, "zstd/decompress", corpus, levels, filters, func(level int, msgs []StoredMessage) ([][]byte, simpleDecompressor, func(), error) {
		compressed := make([][]byte, len(msgs))
		for i, msg := range msgs {
			comp, err := zstd.CompressLevel(nil, msg.Data, level)
			if err != nil {
				return nil, nil, nil, err
			}
			compressed[i] = comp
		}
		decompress := func(dst, src []byte) ([]byte, error) {
			return zstd.Decompress(dst[:0], src)
		}
		return compressed, decompress, nil, nil
	})
}

func BenchmarkKlauspostDecompress(b *testing.B) {
	corpus := loadTestCorpus(b)
	levels := parseIntListFromEnv([]string{"ALGODUMP_KLAUSPOST_LEVELS", "ALGODUMP_BENCH_LEVELS"}, defaultKlauspostLevels)
	filters := parseFilterOptions([]string{"ALGODUMP_KLAUSPOST_FILTERS", "ALGODUMP_BENCH_FILTERS"})
	runSimpleDecompressionMatrix(b, "klauspost/decompress", corpus, levels, filters, func(level int, msgs []StoredMessage) ([][]byte, simpleDecompressor, func(), error) {
		enc, err := kzstd.NewWriter(nil, kzstd.WithEncoderLevel(kzstd.EncoderLevel(level)))
		if err != nil {
			return nil, nil, nil, err
		}
		dec, err := kzstd.NewReader(nil)
		if err != nil {
			enc.Close()
			return nil, nil, nil, err
		}
		compressed := make([][]byte, len(msgs))
		for i, msg := range msgs {
			compressed[i] = enc.EncodeAll(msg.Data, make([]byte, 0, 4096))
		}
		decompress := func(dst, src []byte) ([]byte, error) {
			return dec.DecodeAll(src, dst[:0])
		}
		cleanup := func() {
			enc.Close()
			dec.Close()
		}
		return compressed, decompress, cleanup, nil
	})
}

func BenchmarkGozstdWindow(b *testing.B) {
	configs := parseLevelWindowLogList([]string{"ALGODUMP_GOZSTD_WINDOW_LOGS", "ALGODUMP_BENCH_WINDOW_LOGS"}, defaultGozstdWindowLog)
	for _, cfg := range configs {
		b.Run(fmt.Sprintf("gozstd/window/level=%d/windowLog=%d", cfg.level, cfg.windowLog), func(b *testing.B) {
			benchmarkGozstdWindow(b, cfg.level, cfg.windowLog)
		})
	}
}

func BenchmarkKlauspostWindow(b *testing.B) {
	configs := parseLevelWindowList([]string{"ALGODUMP_KLAUSPOST_WINDOWS", "ALGODUMP_BENCH_WINDOWS"}, defaultKlauspostWindows)
	for _, cfg := range configs {
		b.Run(fmt.Sprintf("klauspost/window/level=%d/window=%d", cfg.level, cfg.window), func(b *testing.B) {
			benchmarkKlauspostWindow(b, cfg.level, cfg.window)
		})
	}
}

func BenchmarkKlauspostStream(b *testing.B) {
	configs := parseLevelWindowList([]string{"ALGODUMP_KLAUSPOST_STREAM_WINDOWS", "ALGODUMP_BENCH_STREAM_WINDOWS"}, defaultKlauspostStreamConfigs)
	for _, cfg := range configs {
		b.Run(fmt.Sprintf("klauspost/stream/level=%d/window=%d", cfg.level, cfg.window), func(b *testing.B) {
			benchmarkKlauspostStream(b, cfg.level, cfg.window)
		})
	}
}

func BenchmarkTagSpecificContexts(b *testing.B) {
	configs := parseTagWindowConfigs([]string{"ALGODUMP_TAG_CONTEXTS", "ALGODUMP_BENCH_TAG_CONTEXTS"}, defaultTagContextConfigs)
	for _, cfg := range configs {
		name := fmt.Sprintf("klauspost/tag-specific/level=%d/av=%d/txpp=%d", cfg.level, cfg.avWindow, cfg.txppWindow)
		b.Run(name, func(b *testing.B) {
			benchmarkTagSpecificContexts(b, cfg.level, cfg.avWindow, cfg.txppWindow)
		})
	}
}
