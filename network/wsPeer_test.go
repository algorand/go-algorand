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

package network

import (
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/metrics"
	"github.com/stretchr/testify/require"
)

func TestCheckSlowWritingPeer(t *testing.T) {
	partitiontest.PartitionTest(t)

	now := time.Now()
	peer := wsPeer{
		intermittentOutgoingMessageEnqueueTime: atomic.Int64{},
		wsPeerCore: wsPeerCore{net: &WebsocketNetwork{
			log: logging.TestingLog(t),
		}},
	}
	require.Equal(t, peer.CheckSlowWritingPeer(now), false)

	peer.intermittentOutgoingMessageEnqueueTime.Store(now.UnixNano())
	require.Equal(t, peer.CheckSlowWritingPeer(now), false)

	peer.intermittentOutgoingMessageEnqueueTime.Store(now.Add(-maxMessageQueueDuration * 2).UnixNano())
	require.Equal(t, peer.CheckSlowWritingPeer(now), true)

}

// TestGetRequestNonce tests if unique values are generated each time
func TestGetRequestNonce(t *testing.T) {
	partitiontest.PartitionTest(t)

	numValues := 1000
	peer := wsPeer{}
	valueChannel := make(chan uint64, numValues)
	for x := 0; x < numValues; x++ {
		go func() {
			ans := peer.getRequestNonce()
			val, _ := binary.Uvarint(ans)
			valueChannel <- val
		}()
	}

	// Timeout
	maxWait := time.After(2 * time.Second)

	// check if all the values are unique
	seenValue := make([]bool, numValues+1)
	for x := 0; x < numValues; x++ {
		select {
		case val := <-valueChannel:
			require.Equal(t, false, seenValue[val])
			seenValue[val] = true
		case <-maxWait:
			break
		}
	}
	// Check if all the values were generated
	for x := 1; x <= numValues; x++ {
		require.Equal(t, true, seenValue[x])
	}
}

func TestDefaultMessageTagsLength(t *testing.T) {
	partitiontest.PartitionTest(t)

	for tag := range defaultSendMessageTags {
		require.Equal(t, 2, len(tag))
	}
}

func TestTagCounterFiltering(t *testing.T) {
	partitiontest.PartitionTest(t)

	tagCounterTags := map[string]*metrics.TagCounter{
		"networkSentBytesByTag":       networkSentBytesByTag,
		"networkReceivedBytesByTag":   networkReceivedBytesByTag,
		"networkMessageReceivedByTag": networkMessageReceivedByTag,
		"networkMessageSentByTag":     networkMessageSentByTag,
	}
	for name, tag := range tagCounterTags {
		t.Run(name, func(t *testing.T) {
			require.NotZero(t, len(tag.AllowedTags))
			tag.Add("TEST_TAG", 1)
			b := strings.Builder{}
			tag.WriteMetric(&b, "")
			result := b.String()
			require.Contains(t, result, "_UNK")
			require.NotContains(t, result, "TEST_TAG")
		})
	}
}

func TestVersionToMajorMinor(t *testing.T) {
	partitiontest.PartitionTest(t)

	ma, mi, err := versionToMajorMinor("1.2")
	require.NoError(t, err)
	require.Equal(t, int64(1), ma)
	require.Equal(t, int64(2), mi)

	ma, mi, err = versionToMajorMinor("1.2.3")
	require.Error(t, err)
	require.Zero(t, ma)
	require.Zero(t, mi)

	ma, mi, err = versionToMajorMinor("1")
	require.Error(t, err)
	require.Zero(t, ma)
	require.Zero(t, mi)

	ma, mi, err = versionToMajorMinor("a.b")
	require.Error(t, err)
	require.Zero(t, ma)
	require.Zero(t, mi)
}

func TestVersionToFeature(t *testing.T) {
	partitiontest.PartitionTest(t)

	tests := []struct {
		ver      string
		hdr      string
		expected peerFeatureFlag
	}{
		{"1.2", "", peerFeatureFlag(0)},
		{"1.2.3", "", peerFeatureFlag(0)},
		{"a.b", "", peerFeatureFlag(0)},
		{"2.1", "", peerFeatureFlag(0)},
		{"2.1", peerFeatureProposalCompression, peerFeatureFlag(0)},
		{"2.2", "", peerFeatureFlag(0)},
		{"2.2", "test", peerFeatureFlag(0)},
		{"2.2", strings.Join([]string{"a", "b"}, ","), peerFeatureFlag(0)},
		{"2.2", peerFeatureProposalCompression, pfCompressedProposal},
		{"2.2", strings.Join([]string{peerFeatureProposalCompression, "test"}, ","), pfCompressedProposal},
		{"2.2", strings.Join([]string{peerFeatureProposalCompression, "test"}, ", "), pfCompressedProposal},
		{"2.2", strings.Join([]string{peerFeatureProposalCompression, peerFeatureVoteVpackCompression}, ","), pfCompressedVoteVpack | pfCompressedProposal},
		{"2.2", peerFeatureVoteVpackCompression, pfCompressedVoteVpack},
		{"2.3", peerFeatureProposalCompression, pfCompressedProposal},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			f := decodePeerFeatures(test.ver, test.hdr)
			require.Equal(t, test.expected, f)
		})
	}
}

func TestPeerReadLoopSwitchAllTags(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	allTags := getProtocolTags(t)
	foundTags := []string{}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "wsPeer.go", nil, 0)
	require.NoError(t, err)

	getCases := func(n ast.Node) (ret bool) {
		switch x := n.(type) {
		case *ast.SwitchStmt:
			// look for "switch msg.Tag"
			if tagSel, ok := x.Tag.(*ast.SelectorExpr); ok {
				if tagSel.Sel.Name != "Tag" {
					return false
				}
				if id, ok := tagSel.X.(*ast.Ident); ok && id.Name != "msg" {
					return false
				}
			}
			// found switch msg.Tag, go through case statements
			for _, s := range x.Body.List {
				cl, ok := s.(*ast.CaseClause)
				if !ok {
					continue
				}
				for i := range cl.List {
					if selExpr, ok := cl.List[i].(*ast.SelectorExpr); ok {
						xid, ok := selExpr.X.(*ast.Ident)
						require.True(t, ok)
						require.Equal(t, "protocol", xid.Name)
						foundTags = append(foundTags, selExpr.Sel.Name)
					}
				}
			}
		}
		return true
	}

	readLoopFound := false
	ast.Inspect(f, func(n ast.Node) bool {
		// look for "readLoop" function
		fn, ok := n.(*ast.FuncDecl)
		if ok && fn.Name.Name == "readLoop" {
			readLoopFound = true
			ast.Inspect(fn, getCases)
			return false
		}
		return true
	})
	require.True(t, readLoopFound)
	require.NotEmpty(t, foundTags)
	// Filter out VP, it's normalized to AV before the switch statement
	allTags = slices.DeleteFunc(allTags, func(tag string) bool { return tag == "VotePackedTag" })
	sort.Strings(allTags)
	sort.Strings(foundTags)
	require.Equal(t, allTags, foundTags)
}

func getProtocolTags(t *testing.T) []string {
	file := filepath.Join("../protocol", "tags.go")
	fset := token.NewFileSet()
	f, _ := parser.ParseFile(fset, file, nil, parser.ParseComments)

	// get deprecated tags
	deprecatedTags := make(map[string]bool)
	for _, d := range f.Decls {
		genDecl, ok := d.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok && len(valueSpec.Names) > 0 &&
				valueSpec.Names[0].Name == "DeprecatedTagList" {
				for _, v := range valueSpec.Values {
					cl, ok := v.(*ast.CompositeLit)
					if !ok {
						continue
					}
					for _, elt := range cl.Elts {
						if ce, ok := elt.(*ast.Ident); ok {
							deprecatedTags[ce.Name] = true
						}
					}
				}
			}
		}
	}

	// look for const declarations in protocol/tags.go
	var declaredTags []string
	// Iterate through the declarations in the file
	for _, d := range f.Decls {
		genDecl, ok := d.(*ast.GenDecl)
		// Check if the declaration is a constant
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		// Iterate through the specs (specifications) in the declaration
		for _, spec := range genDecl.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok {
				if ident, isIdent := valueSpec.Type.(*ast.Ident); !isIdent || ident.Name != "Tag" {
					continue // skip all but Tag constants
				}
				for _, n := range valueSpec.Names {
					if deprecatedTags[n.Name] {
						continue // skip deprecated tags
					}
					declaredTags = append(declaredTags, n.Name)
				}
			}
		}
	}
	// assert these AST-discovered tags are complete (match the size of protocol.TagList)
	require.Len(t, protocol.TagList, len(declaredTags))
	require.Len(t, protocol.DeprecatedTagList, len(deprecatedTags))
	return declaredTags
}

type tcpipMockConn struct{ addr net.TCPAddr }

func (m *tcpipMockConn) RemoteAddr() net.Addr                     { return &m.addr }
func (m *tcpipMockConn) RemoteAddrString() string                 { return "" }
func (m *tcpipMockConn) NextReader() (int, io.Reader, error)      { return 0, nil, nil }
func (m *tcpipMockConn) WriteMessage(int, []byte) error           { return nil }
func (m *tcpipMockConn) CloseWithMessage([]byte, time.Time) error { return nil }
func (m *tcpipMockConn) SetReadLimit(int64)                       {}
func (m *tcpipMockConn) CloseWithoutFlush() error                 { return nil }
func (m *tcpipMockConn) UnderlyingConn() net.Conn                 { return nil }

func TestWsPeerIPAddr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	conn := &tcpipMockConn{}
	peer := wsPeer{
		conn: conn,
	}
	// some raw IPv4 address
	conn.addr.IP = []byte{127, 0, 0, 1}
	require.Equal(t, []byte{127, 0, 0, 1}, peer.ipAddr())
	require.Equal(t, []byte{127, 0, 0, 1}, peer.RoutingAddr())

	// IPv4 constructed from net.IPv4
	conn.addr.IP = net.IPv4(127, 0, 0, 2)
	require.Equal(t, []byte{127, 0, 0, 2}, peer.ipAddr())
	require.Equal(t, []byte{127, 0, 0, 2}, peer.RoutingAddr())

	// some IPv6 address
	conn.addr.IP = net.IPv6linklocalallrouters
	require.Equal(t, []byte(net.IPv6linklocalallrouters), peer.ipAddr())
	require.Equal(t, []byte(net.IPv6linklocalallrouters[0:8]), peer.RoutingAddr())

	// embedded IPv4 into IPv6
	conn.addr.IP = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 3}
	require.Equal(t, 16, len(conn.addr.IP))
	require.Equal(t, []byte{127, 0, 0, 3}, peer.ipAddr())
	require.Equal(t, []byte{127, 0, 0, 3}, peer.RoutingAddr())
	conn.addr.IP = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 4}
	require.Equal(t, 16, len(conn.addr.IP))
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 4}, peer.ipAddr())
	require.Equal(t, []byte{127, 0, 0, 4}, peer.RoutingAddr())

	// check incoming peer with originAddress set
	conn.addr.IP = []byte{127, 0, 0, 1}
	peer.wsPeerCore.originAddress = "127.0.0.2"
	require.Equal(t, []byte{127, 0, 0, 1}, peer.ipAddr())
	require.Equal(t, []byte{127, 0, 0, 2}, peer.RoutingAddr())
}
