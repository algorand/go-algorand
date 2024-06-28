// Copyright (C) 2019-2024 Algorand, Inc.
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

package metrics

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// TestDHTOpenCensusMetrics ensures both count and distribution stats are properly converted to our metrics
func TestDHTOpenCensusMetrics(t *testing.T) {
	partitiontest.PartitionTest(t)

	defaultBytesDistribution := view.Distribution(1024, 2048, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864, 268435456, 1073741824, 4294967296)

	keyMessageType := tag.MustNewKey("message_type")
	keyPeerID := tag.MustNewKey("peer_id")
	keyInstanceID := tag.MustNewKey("instance_id")

	sentMessages := stats.Int64("my_sent_messages", "Total number of messages sent per RPC", stats.UnitDimensionless)
	receivedBytes := stats.Int64("my_received_bytes", "Total received bytes per RPC", stats.UnitBytes)

	receivedBytesView := &view.View{
		Measure:     receivedBytes,
		TagKeys:     []tag.Key{keyMessageType, keyPeerID, keyInstanceID},
		Aggregation: defaultBytesDistribution,
	}
	sentMessagesView := &view.View{
		Measure:     sentMessages,
		TagKeys:     []tag.Key{keyMessageType, keyPeerID, keyInstanceID},
		Aggregation: view.Count(),
	}

	err := view.Register(receivedBytesView, sentMessagesView)
	require.NoError(t, err)
	defer view.Unregister(receivedBytesView, sentMessagesView)

	ctx := context.Background()
	tags1 := []tag.Mutator{
		tag.Upsert(keyMessageType, "UNKNOWN"),
		tag.Upsert(keyPeerID, "1234"),
		tag.Upsert(keyInstanceID, fmt.Sprintf("%p", t)),
	}
	ctx1, _ := tag.New(ctx, tags1...)

	stats.Record(ctx1,
		sentMessages.M(1),
		receivedBytes.M(int64(100)),
	)

	tags2 := []tag.Mutator{
		tag.Upsert(keyMessageType, "ADD_PROVIDER"),
		tag.Upsert(keyPeerID, "abcd"),
		tag.Upsert(keyInstanceID, fmt.Sprintf("%p", t)),
	}
	ctx2, _ := tag.New(ctx, tags2...)

	stats.Record(ctx2,
		sentMessages.M(1),
		receivedBytes.M(int64(123)),
	)

	// first check some metrics are collected when no names provided
	// cannot assert on specific values because network tests might run in parallel with this package
	// and produce some metric under specific configuration
	require.Eventually(t, func() bool {
		// stats are written by a background goroutine, give it a chance to finish
		metrics := collectOpenCensusMetrics(nil)
		return len(metrics) >= 2
	}, 10*time.Second, 20*time.Millisecond)

	// now assert on specific names and values
	metrics := collectOpenCensusMetrics([]string{"my_sent_messages", "my_received_bytes"})
	require.Len(t, metrics, 2)
	for _, m := range metrics {
		var buf strings.Builder
		m.WriteMetric(&buf, "")
		promValue := buf.String()
		if strings.Contains(promValue, "my_sent_messages") {
			require.Contains(t, promValue, "my_sent_messages counter\n")
			require.Contains(t, promValue, `peer_id="abcd"`)
			require.Contains(t, promValue, `peer_id="1234"`)
			require.Contains(t, promValue, `message_type="ADD_PROVIDER"`)
			require.Contains(t, promValue, `message_type="UNKNOWN"`)
			require.Contains(t, promValue, "} 1\n")
		} else if strings.Contains(promValue, "my_received_bytes") {
			require.Contains(t, promValue, "my_received_bytes gauge\n")
			require.Contains(t, promValue, `peer_id="1234"`)
			require.Contains(t, promValue, `peer_id="abcd"`)
			require.Contains(t, promValue, `message_type="ADD_PROVIDER"`)
			require.Contains(t, promValue, `message_type="UNKNOWN"`)
			require.Contains(t, promValue, "} 123\n")
			require.Contains(t, promValue, "} 100\n")
		} else {
			require.Fail(t, "not expected metric", promValue)
		}

		values := make(map[string]float64)
		m.AddMetric(values)
		for k, v := range values {
			require.True(t, strings.Contains(k, "message_type__ADD_PROVIDER") || strings.Contains(k, "message_type__UNKNOWN"))
			require.True(t, strings.Contains(k, "peer_id__1234") || strings.Contains(k, "peer_id__abcd"))
			if strings.Contains(k, "my_sent_messages") {
				require.Equal(t, v, float64(1))
			} else if strings.Contains(k, "my_received_bytes") {
				require.True(t, v == 100 || v == 123)
			} else {
				require.Fail(t, "not expected metric key", k)
			}
		}
	}

	// ensure the exported gatherer works
	reg := MakeRegistry()
	reg.Register(&OpencensusDefaultMetrics)
	defer reg.Deregister(&OpencensusDefaultMetrics)

	var buf strings.Builder
	reg.WriteMetrics(&buf, "")

	require.Contains(t, buf.String(), "my_sent_messages")
	require.Contains(t, buf.String(), "my_received_bytes")
}
