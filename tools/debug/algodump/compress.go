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
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DataDog/zstd"
	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/network/vpack"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-deadlock"
	kzstd "github.com/klauspost/compress/zstd"
	"github.com/valyala/gozstd"
)

// Compression-specific flags
var compress = flag.Bool("compress", false, "Compress messages and show statistics")
var dictionaryFile = flag.String("dict", "", "Path to zstd dictionary file to use for compression")
var compressionLevel = flag.Int("level", 3, "Compression level (1-9, higher = better compression but slower)")
var printCompressGrow = flag.Bool("printCompressGrow", false, "Print hex dump of messages that grow after compression")
var storeDir = flag.String("store", "", "Directory to store messages in")
var storeBatchSize = flag.Int("storeBatch", 1024*1024, "Flush messages to disk after accumulating this many bytes")
var compressionWindowSize = flag.Int("windowSize", 32768, "Compression window size in bytes")
var contextConfig = flag.String("contextcfg", "", "Configure tag-specific compression contexts with window sizes. Format: TAG1:size1;TAG2,TAG3:size2 (e.g. AV:4096;TX,PP:32768)")
var useGozstd = flag.Bool("useGozstd", false, "Use gozstd (C implementation) instead of klauspost (Go implementation) for compression contexts")
var useVpack = flag.Bool("useVpack", false, "Use vpack compression library (optimized for AgreementVote messages) instead of zstd")

// CompressionInterface defines the methods needed for a compression implementation
type CompressionInterface interface {
	Write(p []byte) (n int, err error)
	Flush() error
	Close() error
}

// GozstdWriterAdapter adapts the gozstd Writer to implement our CompressionInterface
type GozstdWriterAdapter struct {
	writer    *gozstd.Writer
	buf       *bytes.Buffer
	level     int
	windowLog int
}

func NewGozstdWriterAdapter(buf *bytes.Buffer, level, windowLog int, cd *gozstd.CDict) *GozstdWriterAdapter {
	// Create parameters including dictionary if provided
	params := &gozstd.WriterParams{
		CompressionLevel: level,
		WindowLog:        windowLog,
		Dict:             cd,
	}
	writer := gozstd.NewWriterParams(buf, params)

	return &GozstdWriterAdapter{
		writer:    writer,
		buf:       buf,
		level:     level,
		windowLog: windowLog,
	}
}

func (a *GozstdWriterAdapter) Write(p []byte) (n int, err error) {
	return a.writer.Write(p)
}

func (a *GozstdWriterAdapter) Flush() error {
	return a.writer.Flush()
}

func (a *GozstdWriterAdapter) Close() error {
	return a.writer.Close()
}

// CompressionContext holds the state for a compression context, which can use either
// klauspost/zstd (pure Go) or valyala/gozstd (C-based) implementation
type CompressionContext struct {
	w        CompressionInterface // Interface that wraps either klauspost or gozstd writer
	buf      *bytes.Buffer        // Buffer to hold compressed data
	cnt      uint64               // Counter for bytes processed
	isGozstd bool                 // Whether this context uses gozstd
}

type tagStats struct {
	originalBytes   uint64
	compressedBytes uint64
	messageCount    uint64
	contextBytes    uint64
	mu              deadlock.Mutex
}

// compressDumpHandler extends dumpHandler with compression functionality
type compressDumpHandler struct {
	*dumpHandler // Embed the original dumpHandler
	stats        map[protocol.Tag]*tagStats
	statsMutex   deadlock.Mutex
	compressor   *zstd.BulkProcessor
	contexts     map[string]*CompressionContext
	contextMu    deadlock.Mutex
	dict         []byte
	cdict        *gozstd.CDict // Reusable gozstd dictionary

	// vpack-related fields
	vpackEncoder *vpack.StatelessEncoder
	vpackDecoder *vpack.StatelessDecoder

	// Tag-specific context configuration
	tagContexts   map[protocol.Tag]int    // Maps tag to window size
	tagGroups     map[protocol.Tag]string // Maps tag to group name for shared contexts
	tagContextsMu deadlock.Mutex
}

// setupCompressSignalHandler sets up a signal handler for the compressDumpHandler
func setupCompressSignalHandler(dh *compressDumpHandler) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		// Flush any remaining messages
		if *storeDir != "" {
			dh.storeMutex.Lock()
			err := dh.flushMessages()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error flushing messages: %v\n", err)
			}
			dh.storeMutex.Unlock()
		}
		// Print compression stats on exit
		dh.printStats()
		os.Exit(0)
	}()
}

// Handle implements the network.MessageHandler interface for compressDumpHandler
func (dh *compressDumpHandler) Handle(msg network.IncomingMessage) network.OutgoingMessage {
	// First check if we should handle this message based on tag filtering
	if dh.tags != nil && !dh.tags[msg.Tag] {
		return network.OutgoingMessage{Action: network.Ignore}
	}

	var src string
	// In playback mode, create a fake peer if none exists
	if msg.Sender == nil && *playbackDir != "" {
		msg.Sender = &fakePeer{}
	}

	hp, ok := msg.Sender.(network.HTTPPeer)
	if ok {
		a := hp.GetAddress()
		if a != *serverAddress {
			src = " " + hp.GetAddress()
		}
	}

	ts := time.Now().Format("15:04:05.000000")
	var txnstr string
	// Extract message data (reuse code from original dumpHandler)
	switch msg.Tag {
	case protocol.AgreementVoteTag:
		var v agreement.UnauthenticatedVote
		err := protocol.Decode(msg.Data, &v)
		if err != nil {
			txnstr = fmt.Sprintf("[decode error: %v]", err)
			goto compress
		}

		txnstr = fmt.Sprintf("%d/%d/%d from %s for %s", v.R.Round, v.R.Period, v.R.Step, shortaddr(v.R.Sender), shortdigest(v.R.Proposal.BlockDigest))

	case protocol.ProposalPayloadTag:
		var p agreement.TransmittedPayload
		err := protocol.Decode(msg.Data, &p)
		if err != nil {
			txnstr = fmt.Sprintf("[decode error: %v]", err)
			goto compress
		}

		txnstr = fmt.Sprintf("proposal %s", shortdigest(crypto.Digest(p.Block.Hash())))

	case protocol.TxnTag:
		dec := protocol.NewMsgpDecoderBytes(msg.Data)
		for {
			var stx transactions.SignedTxn
			err := dec.Decode(&stx)
			if err == io.EOF {
				break
			}
			if err != nil {
				txnstr = fmt.Sprintf("[decode error: %v]", err)
				goto compress
			}
			if len(txnstr) > 0 {
				txnstr = txnstr + ", "
			}
			txnstr = txnstr + fmt.Sprintf("%s from %s", stx.Txn.Type, shortaddr(stx.Txn.Sender))
		}
	}

compress:
	// Compress the message and update statistics
	dh.statsMutex.Lock()
	if dh.stats[msg.Tag] == nil {
		dh.stats[msg.Tag] = &tagStats{}
	}
	stats := dh.stats[msg.Tag]
	dh.statsMutex.Unlock()

	var compressed []byte
	var err error
	var contextCompressed []byte
	var vpackCompressed []byte

	// If using vpack, try to compress the message with vpack first
	if *useVpack && dh.vpackEncoder != nil {
		if msg.Tag == protocol.AgreementVoteTag {
			// Use vpack compression for Agreement Vote messages
			vpackCompressed, err = dh.vpackEncoder.CompressVote(nil, msg.Data)
			if err != nil {
				// Log error but continue with standard compression
				fmt.Fprintf(os.Stderr, "vpack CompressVote error: %v\n", err)
			}
		}
	}

	// Handle context reuse compression first (if not using vpack or vpack failed or message is not an AV)
	if !*useVpack || vpackCompressed == nil {
		if hp, ok := msg.Sender.(network.HTTPPeer); ok {
			addr := hp.GetAddress()
			// Add the tag group or tag as a suffix if we have tag-specific contexts configured
			contextKey := addr
			windowSize := *compressionWindowSize

			dh.tagContextsMu.Lock()
			if len(dh.tagContexts) > 0 {
				if tagWindowSize, ok := dh.tagContexts[msg.Tag]; ok {
					// Use the group name if this tag belongs to a group
					if groupName, ok := dh.tagGroups[msg.Tag]; ok {
						contextKey = addr + "-" + groupName
					} else {
						contextKey = addr + "-" + string(msg.Tag)
					}
					windowSize = tagWindowSize
				}
			}
			dh.tagContextsMu.Unlock()

			dh.contextMu.Lock()
			ctx := dh.contexts[contextKey]
			if ctx == nil {
				// Create new context
				buf := &bytes.Buffer{}

				if *useGozstd {
					// Calculate window log from window size (converting bytes to power of 2)
					windowLog := 0
					size := windowSize
					for size > 1 {
						size >>= 1
						windowLog++
					}
					// Clamp to valid gozstd window log range
					if windowLog < gozstd.WindowLogMin {
						windowLog = gozstd.WindowLogMin
					} else if windowLog > gozstd.WindowLogMax64 {
						windowLog = gozstd.WindowLogMax64
					}

					// Create adapter for gozstd writer that implements CompressionInterface
					adapter := NewGozstdWriterAdapter(buf, *compressionLevel, windowLog, dh.cdict)

					// Create compression context
					ctx = &CompressionContext{
						w:        adapter,
						buf:      buf,
						isGozstd: true,
					}
				} else {
					// Use klauspost implementation (pure Go)
					klevel := kzstd.EncoderLevelFromZstd(*compressionLevel)
					opts := []kzstd.EOption{
						kzstd.WithEncoderLevel(klevel),
						kzstd.WithWindowSize(windowSize),
					}
					if dh.dict != nil {
						opts = append(opts, kzstd.WithEncoderDict(dh.dict))
					}
					w, err := kzstd.NewWriter(buf, opts...)
					if err != nil {
						log.Fatalf("Failed to create klauspost zstd writer: %v", err)
					}
					ctx = &CompressionContext{w: w, buf: buf}
				}

				dh.contexts[contextKey] = ctx
			}

			// Write message to context
			ctx.buf.Reset()
			_, err = ctx.w.Write(msg.Data)
			if err != nil {
				log.Fatalf("Error writing to compression context: %v", err)
			}
			err = ctx.w.Flush()
			if err != nil {
				log.Fatalf("Error flushing compression context: %v", err)
			}
			ctx.cnt += uint64(len(msg.Data))
			contextCompressed = ctx.buf.Bytes()
			dh.contextMu.Unlock()
		}

		// Do regular compression for comparison
		if dh.compressor != nil {
			// Use dictionary-based compression
			compressed, err = dh.compressor.Compress(nil, msg.Data)
		} else {
			// Use standard compression
			compressed, err = zstd.Compress(nil, msg.Data)
		}
		if err != nil {
			log.Fatalf("Error compressing data: %v", err)
		}
	} else {
		// Use the vpack compressed data if available
		compressed = vpackCompressed
	}

	stats.mu.Lock()
	stats.originalBytes += uint64(len(msg.Data))
	stats.compressedBytes += uint64(len(compressed))
	if len(contextCompressed) > 0 {
		stats.contextBytes += uint64(len(contextCompressed))
	}
	stats.messageCount++
	stats.mu.Unlock()

	if !*quiet {
		reduction := (1.0 - float64(len(compressed))/float64(len(msg.Data))) * 100
		output := fmt.Sprintf("%s%s %s [%d->%d bytes %.1f%% reduction]",
			ts, src, msg.Tag,
			len(msg.Data), len(compressed),
			reduction)

		if len(contextCompressed) > 0 {
			ctxReduction := (1.0 - float64(len(contextCompressed))/float64(len(msg.Data))) * 100
			ctxInfo := fmt.Sprintf(" [ctx: %d bytes %.1f%% reduction]",
				len(contextCompressed), ctxReduction)

			dh.tagContextsMu.Lock()
			if tagWindowSize, ok := dh.tagContexts[msg.Tag]; ok {
				ctxInfo = fmt.Sprintf(" [ctx(%s:%d): %d bytes %.1f%% reduction]",
					string(msg.Tag), tagWindowSize, len(contextCompressed), ctxReduction)
			}
			dh.tagContextsMu.Unlock()

			output += ctxInfo
		}

		if len(txnstr) > 0 {
			output += " " + txnstr
		}

		fmt.Println(output)

		// Print if compression made it bigger
		if *printCompressGrow && len(compressed) > len(msg.Data) {
			fmt.Printf("Message grew after compression! Original (%d bytes):\n", len(msg.Data))
			fmt.Printf("%x\n", msg.Data)
			fmt.Printf("Compressed (%d bytes):\n", len(compressed))
			fmt.Printf("%x\n", compressed)
			fmt.Println()
		}
	}

	// Store message if enabled - use the base handler's store functionality
	if *storeDir != "" {
		dh.storeMutex.Lock()
		dh.storeBuffer = append(dh.storeBuffer, StoredMessage{Tag: msg.Tag, Data: msg.Data})
		dh.storeSize += len(msg.Data)

		// Flush if we've exceeded batch size
		if dh.storeSize >= *storeBatchSize {
			err := dh.flushMessages()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error flushing messages: %v\n", err)
			}
		}
		dh.storeMutex.Unlock()
	}

	return network.OutgoingMessage{Action: network.Ignore}
}

// printStats prints the compression statistics
func (dh *compressDumpHandler) printStats() {
	dh.statsMutex.Lock()
	defer dh.statsMutex.Unlock()

	fmt.Println("\nCompression Statistics:")

	// If using vpack, include that in the header
	if *useVpack {
		fmt.Println("Using vpack compression library for AgreementVote messages")
	}

	fmt.Println("Tag     Messages     Original % of Total   Compressed    Ratio     CtxBytes CtxRatio WindowSize")
	fmt.Println("----- ---------- ------------ ---------- ------------ -------- ------------ -------- ----------")

	// Calculate total original bytes first
	var totalOrig, totalComp, totalCtx uint64
	for tag := range dh.stats {
		stats := dh.stats[tag]
		stats.mu.Lock()
		totalOrig += stats.originalBytes
		stats.mu.Unlock()
	}

	// Get all tags and sort them
	tags := make([]protocol.Tag, 0, len(dh.stats))
	for tag := range dh.stats {
		tags = append(tags, tag)
	}
	sort.Slice(tags, func(i, j int) bool {
		return string(tags[i]) < string(tags[j])
	})
	for _, tag := range tags {
		stats := dh.stats[protocol.Tag(tag)]
		stats.mu.Lock()
		var reduction float64
		if stats.originalBytes > 0 {
			reduction = (1.0 - float64(stats.compressedBytes)/float64(stats.originalBytes)) * 100
		}
		ctxReduction := 0.0
		if stats.originalBytes > 0 {
			ctxReduction = (1.0 - float64(stats.contextBytes)/float64(stats.originalBytes)) * 100
		}
		windowSize := *compressionWindowSize
		dh.tagContextsMu.Lock()
		if tagWindowSize, ok := dh.tagContexts[protocol.Tag(tag)]; ok {
			windowSize = tagWindowSize
		}
		dh.tagContextsMu.Unlock()

		// Calculate percentage of total traffic
		pctOfTotal := 0.0
		if totalOrig > 0 {
			pctOfTotal = float64(stats.originalBytes) / float64(totalOrig) * 100.0
		}

		// Add vpack indicator for AgreementVote messages when using vpack
		tagDisplay := string(tag)
		if *useVpack && tag == protocol.AgreementVoteTag {
			tagDisplay = string(tag) + "*" // Add asterisk to indicate vpack compression
		}

		fmt.Printf("%-5s %10d %12d %8.1f%% %12d %7.1f%% %12d %7.1f%% %10d\n",
			tagDisplay,
			stats.messageCount,
			stats.originalBytes,
			pctOfTotal,
			stats.compressedBytes,
			reduction,
			stats.contextBytes,
			ctxReduction,
			windowSize)
		totalComp += stats.compressedBytes
		totalCtx += stats.contextBytes
		stats.mu.Unlock()
	}

	if totalOrig > 0 {
		fmt.Println("----- ---------- ------------ ---------- ------------ -------- ------------ -------- ----------")
		reduction := (1.0 - float64(totalComp)/float64(totalOrig)) * 100
		ctxReduction := (1.0 - float64(totalCtx)/float64(totalOrig)) * 100
		fmt.Printf("%-5s %10s %12d %8.1f%% %12d %7.1f%% %12d %7.1f%% %10s\n",
			"TOTAL", "-", totalOrig, 100.0, totalComp, reduction, totalCtx, ctxReduction, "-")

		// Add a legend for vpack if enabled
		if *useVpack {
			fmt.Println("\n* AV tag uses vpack compression optimized for AgreementVote messages")
		}
	}
}

// initCompressDumpHandler initializes a compressDumpHandler
func initCompressDumpHandler() *compressDumpHandler {
	dh := initDumpHandler() // Start with base handler

	cdh := &compressDumpHandler{
		dumpHandler: dh,
		stats:       make(map[protocol.Tag]*tagStats),
		contexts:    make(map[string]*CompressionContext),
		tagContexts: make(map[protocol.Tag]int),
		tagGroups:   make(map[protocol.Tag]string),
	}

	// Initialize vpack encoder/decoder if -useVpack flag is enabled
	if *useVpack {
		fmt.Println("Using vpack compression library")
		cdh.vpackEncoder = vpack.NewStatelessEncoder()
		cdh.vpackDecoder = vpack.NewStatelessDecoder()
	}

	// Initialize dictionary-based compression if a dictionary file is provided
	if *dictionaryFile != "" && !*useVpack { // Don't use dictionary with vpack
		fmt.Printf("Using dictionary-based compression with %s\n", *dictionaryFile)
		var err error
		cdh.dict, err = os.ReadFile(*dictionaryFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading dictionary file: %v\n", err)
			os.Exit(1)
		}

		// Create a bulk processor with the dictionary
		cdh.compressor, err = zstd.NewBulkProcessor(cdh.dict, *compressionLevel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating dictionary processor: %v\n", err)
			os.Exit(1)
		}

		// If using gozstd, create the reusable dictionary for it too
		if *useGozstd {
			cdh.cdict, err = gozstd.NewCDictLevel(cdh.dict, *compressionLevel)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating gozstd compression dictionary: %v\n", err)
				os.Exit(1)
			}
		}
	}

	return cdh
}

func parseContextConfig(config string) (map[protocol.Tag]int, map[protocol.Tag]string, error) {
	if config == "" {
		return nil, nil, nil
	}

	result := make(map[protocol.Tag]int)    // Maps tag to window size
	groups := make(map[protocol.Tag]string) // Maps tag to group name
	groupNum := 0

	configGroups := strings.Split(config, ";")

	for _, group := range configGroups {
		parts := strings.Split(group, ":")
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid context config format: %s", group)
		}

		tagList := strings.Split(parts[0], ",")
		windowSize, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid window size %s: %v", parts[1], err)
		}

		// Validate window size
		if !isPowerOfTwo(windowSize) {
			return nil, nil, fmt.Errorf("window size must be a power of 2: %d", windowSize)
		}

		if *useGozstd {
			// Calculate window log from window size
			windowLog := 0
			size := windowSize
			for size > 1 {
				size >>= 1
				windowLog++
			}

			// Validate against gozstd constraints
			if windowLog < gozstd.WindowLogMin || windowLog > gozstd.WindowLogMax64 {
				return nil, nil, fmt.Errorf("for gozstd, window size must be between %d and %d bytes: %d",
					1<<gozstd.WindowLogMin, 1<<gozstd.WindowLogMax64, windowSize)
			}
		} else {
			// Validate against klauspost constraints
			if windowSize < kzstd.MinWindowSize || windowSize > kzstd.MaxWindowSize {
				return nil, nil, fmt.Errorf("for klauspost, window size must be between %d and %d: %d",
					kzstd.MinWindowSize, kzstd.MaxWindowSize, windowSize)
			}
		}

		// Create a group name for this set of tags
		groupName := fmt.Sprintf("group%d", groupNum)
		groupNum++

		// Add each tag with the specified window size and group
		for _, tag := range tagList {
			tagStr := protocol.Tag(tag)
			result[tagStr] = windowSize
			groups[tagStr] = groupName
		}
	}

	return result, groups, nil
}

// configureCompression sets up tag-specific contexts for the compressDumpHandler
func configureCompression(dh *compressDumpHandler) error {
	// Configure tag-specific contexts if provided
	if *contextConfig != "" {
		tagContexts, tagGroups, err := parseContextConfig(*contextConfig)
		if err != nil {
			return fmt.Errorf("error parsing context configuration: %v", err)
		}
		dh.tagContexts = tagContexts
		dh.tagGroups = tagGroups

		// Print a more user-friendly summary of the configuration
		libraryName := "klauspost/zstd (Go)"
		if *useGozstd {
			libraryName = "valyala/gozstd (C)"
		}
		fmt.Printf("Configured compression contexts using %s library:\n", libraryName)

		// Group tags by their group name for shared contexts
		groupedTags := make(map[string][]string)
		groupSizes := make(map[string]int)
		for tag, group := range tagGroups {
			groupedTags[group] = append(groupedTags[group], string(tag))
			groupSizes[group] = tagContexts[tag]
		}

		// Print each context group
		for group, tags := range groupedTags {
			fmt.Printf("  Context %s: tags [%s] with window size %d bytes\n",
				group, strings.Join(tags, ","), groupSizes[group])
		}
	}
	return nil
}
