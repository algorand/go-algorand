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
		fmt.Printf("Loaded %d messages (%.2f MB) from %d files across %d directories:\n",
			len(corpus.messages),
			float64(corpus.total)/1024/1024,
			totalFiles,
			len(dirCounts))

		// Print per-directory counts
		for dir, count := range dirCounts {
			if count > 0 {
				fmt.Printf("  - %s: %d messages\n", dir, count)
			}
		}

		// Print message counts by tag
		fmt.Println("Messages by tag:")

		for _, tagStr := range slices.Sorted(maps.Keys(tagCounts)) {
			tag := protocol.Tag(tagStr)
			fmt.Printf("  - %s: %d messages\n", tagStr, tagCounts[tag])
		}
	}

	if len(corpus.messages) == 0 {
		t.Skip("no message files found in any test directory")
	}

	// Cache the corpus for future calls
	cachedCorpus = &corpus
	return cachedCorpus
}

// benchmarkVPackCompression benchmarks the vpack compression implementation
func benchmarkVPackCompression(b *testing.B) {
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
			b.Fatalf("ParseVoteMsgpack failed: %v", err)
		}
		totalCompressed += int64(len(compressed))
		origBytes += int64(len(msg.Data))
	}
	b.StopTimer()

	b.ReportMetric(float64(origBytes)/float64(totalCompressed), "ratio")
	b.ReportMetric(100-float64(totalCompressed)/float64(origBytes)*100, "%smaller")
	b.SetBytes(origBytes / int64(b.N))
}

// benchmarkVPackDecompression benchmarks the vpack decompression implementation
func benchmarkVPackDecompression(b *testing.B) {
	corpus := loadTestCorpus(b)

	// First compress all AV messages to have compressed data for benchmark
	filtered := filterMessages(b, corpus, true)
	compressedData := make([][]byte, 0, len(filtered))
	var origCnt, encCnt int64

	enc := vpack.NewStatelessEncoder()

	// Pre-compress the messages
	for _, msg := range filtered {
		encBytes, err := enc.CompressVote(nil, msg.Data)
		if err != nil {
			b.Fatalf("ParseVoteMsgpack failed during setup: %v", err)
		}
		compressedData = append(compressedData, encBytes)
		origCnt += int64(len(msg.Data))
		encCnt += int64(len(encBytes))
	}

	if len(compressedData) == 0 {
		b.Fatal("No compressed data to benchmark")
	}

	b.ResetTimer()
	var totalDecompressed int64
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

	b.SetBytes(encCnt / int64(b.N))
}

// benchmarkGozstdSimple benchmarks the valyala/gozstd implementation
// with a new context for each message (simple, no window sharing)
func benchmarkGozstdSimple(b *testing.B, level int, onlyAV bool) {
	corpus := loadTestCorpus(b)

	// Filter messages based on criteria
	filtered := filterMessages(b, corpus, onlyAV)

	// Pre-allocate a buffer to hold compressed data
	// Initial capacity of 4KB should handle most messages
	compressed := make([]byte, 0, 4096)

	b.ResetTimer()
	var totalCompressed int64
	var origBytes int64
	for i := 0; i < b.N; i++ {
		// Process one message per iteration, cycling through messages
		msg := filtered[i%len(filtered)]

		// Reuse the same buffer, slicing to zero length to reset it
		compressed = gozstd.CompressLevel(compressed[:0], msg.Data, level)
		totalCompressed += int64(len(compressed))
		origBytes += int64(len(msg.Data))
	}
	b.StopTimer()

	b.ReportMetric(float64(origBytes)/float64(totalCompressed), "ratio")
	b.ReportMetric(100-float64(totalCompressed)/float64(origBytes)*100, "%smaller")
	b.SetBytes(origBytes / int64(b.N))
}

// benchmarkZstdSimple benchmarks the datadog/zstd implementation
// with a new context for each message (simple, no window sharing)
func benchmarkZstdSimple(b *testing.B, level int, onlyAV bool) {
	corpus := loadTestCorpus(b)

	// Filter messages based on criteria
	filtered := filterMessages(b, corpus, onlyAV)

	// Pre-allocate a buffer to hold compressed data
	// Initial capacity of 4KB should handle most messages
	compressed := make([]byte, 0, 4096)

	b.ResetTimer()
	var totalCompressed int64
	var origBytes int64
	for i := 0; i < b.N; i++ {
		// Process one message per iteration, cycling through messages
		msg := filtered[i%len(filtered)]

		// Reuse the same buffer, slicing to zero length to reset it
		var err error
		compressed, err = zstd.CompressLevel(compressed[:0], msg.Data, level)
		_ = err
		totalCompressed += int64(len(compressed))
		origBytes += int64(len(msg.Data))
	}
	b.StopTimer()

	b.ReportMetric(float64(origBytes)/float64(totalCompressed), "ratio")
	b.ReportMetric(100-float64(totalCompressed)/float64(origBytes)*100, "%smaller")
	b.SetBytes(origBytes / int64(b.N))
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

	b.ResetTimer()
	var totalCompressed int64
	var origBytes int64
	for i := 0; i < b.N; i++ {
		// Process one message per iteration, cycling through filtered messages
		msg := filtered[i%len(filtered)]

		// Reset buffer before each message
		buf.Reset()

		// Compress the message
		_, _ = zw.Write(msg.Data)
		_ = zw.Flush() // Use Flush instead of Close to keep the writer active

		totalCompressed += int64(buf.Len())
		origBytes += int64(len(msg.Data))
	}
	b.StopTimer()

	b.ReportMetric(float64(origBytes)/float64(totalCompressed), "ratio")
	b.ReportMetric(100-float64(totalCompressed)/float64(origBytes)*100, "%smaller")
	b.SetBytes(origBytes / int64(b.N)) // For MB/s calculation, use per-iteration bytes
}

// benchmarkKlauspostSimple benchmarks the Klauspost zstd implementation
// with a new encoder for each message (simple, no window sharing)
func benchmarkKlauspostSimple(b *testing.B, level int, onlyAV bool) {
	corpus := loadTestCorpus(b)

	// Filter messages based on criteria
	filtered := filterMessages(b, corpus, onlyAV)

	// Create a single encoder to reuse for all messages
	enc, _ := kzstd.NewWriter(nil, kzstd.WithEncoderLevel(kzstd.EncoderLevel(level)))
	defer enc.Close()

	// Pre-allocate a buffer to hold compressed data
	// Initial capacity of 4KB should handle most messages
	compressed := make([]byte, 0, 4096)

	b.ResetTimer()
	var totalCompressed int64
	var origBytes int64
	for i := 0; i < b.N; i++ {
		// Process one message per iteration, cycling through messages
		msg := filtered[i%len(filtered)]

		// Reuse the same encoder and output buffer for each message
		compressed = enc.EncodeAll(msg.Data, compressed[:0])
		totalCompressed += int64(len(compressed))
		origBytes += int64(len(msg.Data))
	}
	b.StopTimer()

	b.ReportMetric(float64(origBytes)/float64(totalCompressed), "ratio")
	b.ReportMetric(100-float64(totalCompressed)/float64(origBytes)*100, "%smaller")
	b.SetBytes(origBytes / int64(b.N))
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

	// Pre-allocate a buffer that we'll reuse
	compressed := make([]byte, 0, 4096)

	b.ResetTimer()
	var totalCompressed int64
	var origBytes int64
	for i := 0; i < b.N; i++ {
		// Process one message per iteration, cycling through filtered messages
		msg := filtered[i%len(filtered)]

		// Reset the buffer by slicing to zero length
		compressed = enc.EncodeAll(msg.Data, compressed[:0])
		totalCompressed += int64(len(compressed))
		origBytes += int64(len(msg.Data))
	}
	b.StopTimer()

	b.ReportMetric(float64(origBytes)/float64(totalCompressed), "ratio")
	b.ReportMetric(100-float64(totalCompressed)/float64(origBytes)*100, "%smaller")
	b.SetBytes(origBytes / int64(b.N)) // For MB/s calculation, use per-iteration bytes
}

// benchmarkKlauspostStream benchmarks the Klauspost zstd implementation
// with a streaming approach (accumulating context across messages)
func benchmarkKlauspostStream(b *testing.B, level int, windowSize int) {
	corpus := loadTestCorpus(b)

	filtered := filterMessages(b, corpus, false)

	b.ResetTimer()
	var totalCompressed int64
	var origBytes int64
	// Create a buffer and encoder that will be used for all messages in this iteration
	var buf bytes.Buffer
	enc, _ := kzstd.NewWriter(&buf,
		kzstd.WithEncoderLevel(kzstd.EncoderLevel(level)),
		kzstd.WithWindowSize(windowSize))
	defer enc.Close()
	for i := 0; i < b.N; i++ {
		msg := filtered[i%len(filtered)]
		buf.Reset()
		_, _ = enc.Write(msg.Data)
		_ = enc.Flush()
		totalCompressed += int64(buf.Len())
		origBytes += int64(len(msg.Data))
	}
	b.StopTimer()

	b.ReportMetric(float64(origBytes)/float64(totalCompressed), "ratio")
	b.ReportMetric(100-float64(totalCompressed)/float64(origBytes)*100, "%smaller")
	b.SetBytes(origBytes / int64(b.N)) // For MB/s calculation, use per-iteration bytes
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

// Gozstd Simple Benchmarks (no window control)
// Using C zstd levels: 1, 3, 7, 11
func BenchmarkGozstdSimple1(b *testing.B)  { benchmarkGozstdSimple(b, 1, false) }
func BenchmarkGozstdSimple3(b *testing.B)  { benchmarkGozstdSimple(b, 3, false) }
func BenchmarkGozstdSimple7(b *testing.B)  { benchmarkGozstdSimple(b, 7, false) }
func BenchmarkGozstdSimple11(b *testing.B) { benchmarkGozstdSimple(b, 11, false) }

// Gozstd Simple Benchmarks for AV messages only
func BenchmarkGozstdSimpleAV1(b *testing.B)  { benchmarkGozstdSimple(b, 1, true) }
func BenchmarkGozstdSimpleAV3(b *testing.B)  { benchmarkGozstdSimple(b, 3, true) }
func BenchmarkGozstdSimpleAV7(b *testing.B)  { benchmarkGozstdSimple(b, 7, true) }
func BenchmarkGozstdSimpleAV11(b *testing.B) { benchmarkGozstdSimple(b, 11, true) }

// Datadog Zstd Simple Benchmarks (no window control)
func BenchmarkZstdSimple1(b *testing.B)  { benchmarkZstdSimple(b, 1, false) }
func BenchmarkZstdSimple3(b *testing.B)  { benchmarkZstdSimple(b, 3, false) }
func BenchmarkZstdSimple7(b *testing.B)  { benchmarkZstdSimple(b, 7, false) }
func BenchmarkZstdSimple11(b *testing.B) { benchmarkZstdSimple(b, 11, false) }

// Datadog Zstd Simple Benchmarks for AV messages only
func BenchmarkZstdSimpleAV1(b *testing.B)  { benchmarkZstdSimple(b, 1, true) }
func BenchmarkZstdSimpleAV3(b *testing.B)  { benchmarkZstdSimple(b, 3, true) }
func BenchmarkZstdSimpleAV7(b *testing.B)  { benchmarkZstdSimple(b, 7, true) }
func BenchmarkZstdSimpleAV11(b *testing.B) { benchmarkZstdSimple(b, 11, true) }

// Gozstd Window Benchmarks (specific window sizes with different compression levels)
// Window log values (2^N bytes):
// 15 = 32KB window
// 18 = 256KB window
// 20 = 1MB window
func BenchmarkGozstdWindow1_32K(b *testing.B)   { benchmarkGozstdWindow(b, 1, 15) }
func BenchmarkGozstdWindow1_256K(b *testing.B)  { benchmarkGozstdWindow(b, 1, 18) }
func BenchmarkGozstdWindow1_1M(b *testing.B)    { benchmarkGozstdWindow(b, 1, 20) }
func BenchmarkGozstdWindow3_32K(b *testing.B)   { benchmarkGozstdWindow(b, 3, 15) }
func BenchmarkGozstdWindow3_256K(b *testing.B)  { benchmarkGozstdWindow(b, 3, 18) }
func BenchmarkGozstdWindow3_1M(b *testing.B)    { benchmarkGozstdWindow(b, 3, 20) }
func BenchmarkGozstdWindow7_256K(b *testing.B)  { benchmarkGozstdWindow(b, 7, 18) }
func BenchmarkGozstdWindow11_256K(b *testing.B) { benchmarkGozstdWindow(b, 11, 18) }

// Klauspost Simple Benchmarks (new encoder for each message, no window sharing)
func BenchmarkKlauspostSimple1(b *testing.B) { benchmarkKlauspostSimple(b, 1, false) }
func BenchmarkKlauspostSimple3(b *testing.B) { benchmarkKlauspostSimple(b, 3, false) }

// Klauspost Simple Benchmarks for AV messages only
func BenchmarkKlauspostSimpleAV1(b *testing.B) { benchmarkKlauspostSimple(b, 1, true) }
func BenchmarkKlauspostSimpleAV3(b *testing.B) { benchmarkKlauspostSimple(b, 3, true) }

// Klauspost Window Size Benchmarks (with different window sizes)
// Note: Using klauspost levels where:
// Level 1 = "Fastest" ≈ zstd level 1
// Level 2 = "Default" ≈ zstd level 3 (zstd default)
// Level 3 = "Better"  ≈ zstd level 7
// Level 4 = "Best"    ≈ zstd level 11

// Baseline benchmarks with standard window sizes
func BenchmarkKlauspostWindow1_4K(b *testing.B)  { benchmarkKlauspostWindow(b, 1, 1<<12) } // 4KB window
func BenchmarkKlauspostWindow1_64K(b *testing.B) { benchmarkKlauspostWindow(b, 1, 1<<16) } // 64KB window
func BenchmarkKlauspostWindow1_1M(b *testing.B)  { benchmarkKlauspostWindow(b, 1, 1<<20) } // 1MB window

// Algodump-specific window sizes (based on actual usage patterns)
func BenchmarkKlauspostWindow1_32K(b *testing.B)  { benchmarkKlauspostWindow(b, 1, 1<<15) } // 32KB window for TX/PP
func BenchmarkKlauspostWindow1_256K(b *testing.B) { benchmarkKlauspostWindow(b, 1, 1<<18) } // 256KB window for AV

// Higher compression levels with different window sizes
func BenchmarkKlauspostWindow2_32K(b *testing.B)  { benchmarkKlauspostWindow(b, 2, 1<<15) }
func BenchmarkKlauspostWindow2_256K(b *testing.B) { benchmarkKlauspostWindow(b, 2, 1<<18) }
func BenchmarkKlauspostWindow2_1M(b *testing.B)   { benchmarkKlauspostWindow(b, 2, 1<<20) }
func BenchmarkKlauspostWindow3_256K(b *testing.B) { benchmarkKlauspostWindow(b, 3, 1<<18) }
func BenchmarkKlauspostWindow3_1M(b *testing.B)   { benchmarkKlauspostWindow(b, 3, 1<<20) }

// Klauspost Stream Benchmarks (continuous streaming)
// Baseline streaming benchmarks
func BenchmarkKlauspostStream1_4K(b *testing.B) { benchmarkKlauspostStream(b, 1, 1<<12) }
func BenchmarkKlauspostStream1_1M(b *testing.B) { benchmarkKlauspostStream(b, 1, 1<<20) }

// Algodump-specific window sizes for streaming
func BenchmarkKlauspostStream1_32K(b *testing.B)  { benchmarkKlauspostStream(b, 1, 1<<15) } // 32KB for TX/PP
func BenchmarkKlauspostStream1_256K(b *testing.B) { benchmarkKlauspostStream(b, 1, 1<<18) } // 256KB for AV

// Higher compression levels with different window sizes
func BenchmarkKlauspostStream2_32K(b *testing.B)  { benchmarkKlauspostStream(b, 2, 1<<15) }
func BenchmarkKlauspostStream2_256K(b *testing.B) { benchmarkKlauspostStream(b, 2, 1<<18) }
func BenchmarkKlauspostStream2_1M(b *testing.B)   { benchmarkKlauspostStream(b, 2, 1<<20) }
func BenchmarkKlauspostStream3_256K(b *testing.B) { benchmarkKlauspostStream(b, 3, 1<<18) }
func BenchmarkKlauspostStream3_1M(b *testing.B)   { benchmarkKlauspostStream(b, 3, 1<<20) }

// Tag-specific window size benchmarks with actual algodump configurations
// These benchmarks simulate the real-world scenario where different message types
// have their own context windows with specific sizes

// Compression level 1 (Fastest) with various algodump configurations
func BenchmarkTagSpecific1_AV256K_TXPP32K(b *testing.B) {
	benchmarkTagSpecificContexts(b, 1, 1<<18, 1<<15) // 256KB for AV, 32KB for TX/PP
}

func BenchmarkTagSpecific1_AV128K_TXPP32K(b *testing.B) {
	benchmarkTagSpecificContexts(b, 1, 1<<17, 1<<15) // 128KB for AV, 32KB for TX/PP
}

// Compression level 2 (Default) with various algodump configurations
func BenchmarkTagSpecific2_AV256K_TXPP32K(b *testing.B) {
	benchmarkTagSpecificContexts(b, 2, 1<<18, 1<<15) // 256KB for AV, 32KB for TX/PP
}

// Compression level 3 (Better) with various algodump configurations
func BenchmarkTagSpecific3_AV256K_TXPP32K(b *testing.B) {
	benchmarkTagSpecificContexts(b, 3, 1<<18, 1<<15) // 256KB for AV, 32KB for TX/PP
}

// VPack benchmark functions
func BenchmarkVPackCompression(b *testing.B) {
	benchmarkVPackCompression(b)
}

func BenchmarkVPackDecompression(b *testing.B) {
	benchmarkVPackDecompression(b)
}
