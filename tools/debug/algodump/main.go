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
	"os"
	"strings"
	"time"

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
var genesisID = flag.String("genesis", "mainnet-v1.0", "Genesis ID")
var networkID = flag.String("network", "mainnet", "Network ID")
var tags = flag.String("tags", "*", "Comma-separated list of tags to dump, or * for all")
var longFlag = flag.Bool("long", false, "Print full-length addresses and digests")

type dumpHandler struct {
	tags map[protocol.Tag]bool
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

func (dh *dumpHandler) Handle(msg network.IncomingMessage) network.OutgoingMessage {
	var src string

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
	fmt.Printf("%s%s %s [%d bytes] %s\n", ts, src, msg.Tag, len(msg.Data), data)
	return network.OutgoingMessage{Action: network.Ignore}
}

func setDumpHandlers(n network.GossipNode) {
	var dh dumpHandler

	if *tags == "*" {
		// Dump all tags: nil tags
	} else if *tags == "" {
		// Dump nothing: empty tags
		dh.tags = make(map[protocol.Tag]bool)
	} else {
		dh.tags = make(map[protocol.Tag]bool)
		for t := range strings.SplitSeq(*tags, ",") {
			dh.tags[protocol.Tag(t)] = true
			fmt.Printf("TAG <%s>\n", t)
		}
	}

	h := []network.TaggedMessageHandler{
		{Tag: protocol.AgreementVoteTag, MessageHandler: &dh},
		{Tag: protocol.StateProofSigTag, MessageHandler: &dh},
		{Tag: protocol.MsgOfInterestTag, MessageHandler: &dh},
		{Tag: protocol.MsgDigestSkipTag, MessageHandler: &dh},
		{Tag: protocol.NetPrioResponseTag, MessageHandler: &dh},
		// {Tag: protocol.PingTag, MessageHandler: &dh},
		// {Tag: protocol.PingReplyTag, MessageHandler: &dh},
		{Tag: protocol.ProposalPayloadTag, MessageHandler: &dh},
		{Tag: protocol.TopicMsgRespTag, MessageHandler: &dh},
		{Tag: protocol.TxnTag, MessageHandler: &dh},
		{Tag: protocol.UniEnsBlockReqTag, MessageHandler: &dh},
		{Tag: protocol.VoteBundleTag, MessageHandler: &dh},
	}
	n.RegisterHandlers(h)
}

func main() {
	log := logging.Base()
	log.SetLevel(logging.Debug)
	log.SetOutput(os.Stderr)

	if *serverAddress == "" {
		log.Infof("No server address specified; defaulting to DNS bootstrapping")
	}

	deadlock.Opts.Disable = true

	flag.Parse()

	conf, _ := config.LoadConfigFromDisk("/dev/null")
	if *serverAddress != "" {
		conf.DNSBootstrapID = ""
	}

	n, _ := network.NewWebsocketGossipNode(log,
		conf,
		[]string{*serverAddress},
		*genesisID,
		protocol.NetworkID(*networkID))
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
