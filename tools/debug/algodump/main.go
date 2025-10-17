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
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	kzstd "github.com/klauspost/compress/zstd"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

var serverAddress = flag.String("server", "", "Server address (host:port)")
var playbackDir = flag.String("playback", "", "Directory to load stored messages from")
var quiet = flag.Bool("quiet", false, "Suppress printing of individual message details")
var genesisID = flag.String("genesis", "mainnet-v1.0", "Genesis ID")
var networkID = flag.String("network", "mainnet", "Network ID")
var tags = flag.String("tags", "*", "Comma-separated list of tags to dump, or * for all")
var longFlag = flag.Bool("long", false, "Print full-length addresses and digests")

type StoredMessage struct {
	Tag  protocol.Tag `codec:"t"`
	Data []byte       `codec:"d,allocbound=-"`
}

// dumpHandler handles dumping network messages to console/files
type dumpHandler struct {
	tags         map[protocol.Tag]bool
	storeMutex   deadlock.Mutex
	storeBuffer  []StoredMessage
	storeSize    int
	storeCounter int
}

func shortaddr(addr basics.Address) string {
	if *longFlag {
		return addr.String()
	}
	return fmt.Sprintf("%s..", addr.String()[0:8])
}

func shortdigest(d crypto.Digest) string {
	if *longFlag {
		return d.String()
	}
	return fmt.Sprintf("%s..", d.String()[0:8])
}

// fakePeer implements network.DisconnectableAddressablePeer for playback mode
type fakePeer struct{}

func (fp *fakePeer) GetAddress() string             { return "playback-peer" }
func (fp *fakePeer) GetHTTPClient() *http.Client    { return nil }
func (fp *fakePeer) Disconnect(reason string) error { return nil }
func (fp *fakePeer) GetNetwork() network.GossipNode { return nil }
func (fp *fakePeer) RoutingAddr() []byte            { return []byte("playback-peer") }

// Handle implements the network.MessageHandler interface for dumpHandler
func (dh *dumpHandler) Handle(msg network.IncomingMessage) network.OutgoingMessage {
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

	if dh.tags != nil && !dh.tags[msg.Tag] {
		return network.OutgoingMessage{Action: network.Ignore}
	}

	ts := time.Now().Format("15:04:05.000000")
	var data string
	switch msg.Tag {
	case protocol.AgreementVoteTag:
		var v agreement.UnauthenticatedVote
		err := protocol.Decode(msg.Data, &v)
		if err != nil {
			data = fmt.Sprintf("[decode error: %v]", err)
			goto print
		}

		data = fmt.Sprintf("%d/%d/%d from %s for %s", v.R.Round, v.R.Period, v.R.Step, shortaddr(v.R.Sender), shortdigest(v.R.Proposal.BlockDigest))

	case protocol.ProposalPayloadTag:
		var p agreement.TransmittedPayload
		err := protocol.Decode(msg.Data, &p)
		if err != nil {
			data = fmt.Sprintf("[decode error: %v]", err)
			goto print
		}

		data = fmt.Sprintf("proposal %s", shortdigest(crypto.Digest(p.Block.Hash())))

	case protocol.TxnTag:
		dec := protocol.NewMsgpDecoderBytes(msg.Data)
		for {
			var stx transactions.SignedTxn
			err := dec.Decode(&stx)
			if err == io.EOF {
				break
			}
			if err != nil {
				data = fmt.Sprintf("[decode error: %v]", err)
				goto print
			}
			if len(data) > 0 {
				data = data + ", "
			}
			data = data + fmt.Sprintf("%s from %s", stx.Txn.Type, shortaddr(stx.Txn.Sender))
		}
	}

print:
	if !*quiet {
		fmt.Printf("%s%s %s [%d bytes] %s\n", ts, src, msg.Tag, len(msg.Data), data)
	}

	// Store message if enabled
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

// initDumpHandler initializes a basic dumpHandler
func initDumpHandler() *dumpHandler {
	var dh dumpHandler

	// Set up tag filtering
	if *tags == "*" {
		// Dump all tags: nil tags
	} else if *tags == "" {
		// Dump nothing: empty tags
		dh.tags = make(map[protocol.Tag]bool)
	} else {
		dh.tags = make(map[protocol.Tag]bool)
		for _, t := range strings.Split(*tags, ",") {
			dh.tags[protocol.Tag(t)] = true
			fmt.Printf("TAG <%s>\n", t)
		}
	}

	return &dh
}

// setDumpHandlers configures and registers message handlers with the network node
func setDumpHandlers(n network.GossipNode) network.MessageHandler {
	var dh network.MessageHandler

	// Create store directory if needed (for both handler types)
	if *storeDir != "" {
		err := os.MkdirAll(*storeDir, 0755)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating store directory: %v\n", err)
			os.Exit(1)
		}
	}

	// Choose handler type based on compression flag
	if *compress {
		// Initialize and configure compression handler
		cdh := initCompressDumpHandler()
		err := configureCompression(cdh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		dh = cdh
		setupCompressSignalHandler(cdh)
	} else {
		// Use basic handler
		ddh := initDumpHandler()
		dh = ddh
		setupBasicSignalHandler(ddh)
	}

	// Register the handler with all tags
	h := []network.TaggedMessageHandler{
		{Tag: protocol.AgreementVoteTag, MessageHandler: dh},
		{Tag: protocol.StateProofSigTag, MessageHandler: dh},
		{Tag: protocol.MsgOfInterestTag, MessageHandler: dh},
		{Tag: protocol.MsgDigestSkipTag, MessageHandler: dh},
		{Tag: protocol.NetPrioResponseTag, MessageHandler: dh},
		// {Tag: protocol.PingTag, MessageHandler: dh},
		// {Tag: protocol.PingReplyTag, MessageHandler: dh},
		{Tag: protocol.ProposalPayloadTag, MessageHandler: dh},
		{Tag: protocol.TopicMsgRespTag, MessageHandler: dh},
		{Tag: protocol.TxnTag, MessageHandler: dh},
		{Tag: protocol.UniEnsBlockReqTag, MessageHandler: dh},
		{Tag: protocol.VoteBundleTag, MessageHandler: dh},
	}
	n.RegisterHandlers(h)

	return dh
}

// isPowerOfTwo returns true if n is a power of 2
func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// runPlayback processes stored message files from a directory
func runPlayback(log logging.Logger) {
	var handler network.MessageHandler

	// Choose the appropriate handler based on compression flag
	if *compress {
		cdh := initCompressDumpHandler()

		// Configure compression for playback mode
		if *contextConfig != "" {
			err := configureCompression(cdh)
			if err != nil {
				log.Errorf("Error parsing context configuration: %v", err)
				os.Exit(1)
			}
		}
		handler = cdh
	} else {
		handler = initDumpHandler()
	}

	files, err := os.ReadDir(*playbackDir)
	if err != nil {
		log.Errorf("Failed to read playback directory: %v", err)
		os.Exit(1)
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".msgp") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(*playbackDir, file.Name()))
		if err != nil {
			log.Errorf("Failed to read message file %s: %v", file.Name(), err)
			continue
		}
		var messages []StoredMessage
		err = protocol.DecodeReflect(data, &messages)
		if err != nil {
			log.Errorf("Failed to decode messages from %s: %v", file.Name(), err)
			continue
		}

		// Process each message through the appropriate handler
		for _, msg := range messages {
			handler.Handle(network.IncomingMessage{Tag: msg.Tag, Data: msg.Data})
		}
	}

	// Print stats only if using compression
	if *compress {
		cdh := handler.(*compressDumpHandler)
		cdh.printStats()
	}
}

// setupBasicSignalHandler sets up a signal handler for the basic dumpHandler
func setupBasicSignalHandler(dh *dumpHandler) {
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
		os.Exit(0)
	}()
}

func (dh *dumpHandler) flushMessages() error {
	if len(dh.storeBuffer) == 0 {
		return nil
	}

	// Create timestamped filename
	timestamp := time.Now().Format("20060102-150405.000")
	filename := fmt.Sprintf("messages-%s-%d.msgp", timestamp, dh.storeCounter)
	path := filepath.Join(*storeDir, filename)

	// Encode messages
	data := protocol.EncodeReflect(&dh.storeBuffer)

	// Write to file
	err := os.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing messages to %s: %v", path, err)
	}

	// Reset buffer
	dh.storeBuffer = nil
	dh.storeSize = 0
	dh.storeCounter++
	return nil
}

func main() {
	log := logging.Base()
	log.SetLevel(logging.Debug)
	log.SetOutput(os.Stderr)

	flag.Parse()

	// Validate compression parameters if compress is enabled
	if *compress {
		// Validate that window size is a power of 2 and within valid range
		if !isPowerOfTwo(*compressionWindowSize) {
			log.Errorf("windowSize must be a power of 2, got %d", *compressionWindowSize)
			os.Exit(1)
		}
		if *compressionWindowSize < kzstd.MinWindowSize || *compressionWindowSize > kzstd.MaxWindowSize {
			log.Errorf("windowSize must be between %d and %d, got %d",
				kzstd.MinWindowSize, kzstd.MaxWindowSize, *compressionWindowSize)
			os.Exit(1)
		}

		// Parse context configuration if provided - validation only
		if *contextConfig != "" {
			_, _, err := parseContextConfig(*contextConfig)
			if err != nil {
				log.Errorf("Failed to parse context configuration: %v", err)
				os.Exit(1)
			}
		}
	}

	if *playbackDir != "" {
		// Playback mode - process stored messages from a directory
		runPlayback(log)
		os.Exit(0)
	} else {
		// Live mode - connect to network and process messages in real-time
		if *serverAddress == "" {
			log.Infof("No server address specified; defaulting to DNS bootstrapping")
		}

		deadlock.Opts.Disable = true

		conf, _ := config.LoadConfigFromDisk("/dev/null")
		if *serverAddress != "" {
			conf.DNSBootstrapID = ""
		}
		conf.GossipFanout = 1

		n, _ := network.NewWebsocketGossipNode(log,
			conf,
			[]string{*serverAddress},
			*genesisID,
			protocol.NetworkID(*networkID))

		// Set up and register handlers - this detects the -compress flag and sets up the appropriate handler
		setDumpHandlers(n)

		err := n.Start()
		if err != nil {
			log.Errorf("Failed to start network: %v", err)
			return
		}

		for {
			time.Sleep(time.Second)
		}
	}
}
