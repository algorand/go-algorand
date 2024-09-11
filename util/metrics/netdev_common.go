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
	"fmt"
	"strconv"
	"strings"
)

type netDevStats struct {
	bytesReceived uint64
	bytesSent     uint64
	iface         string
}

type netDevGatherer struct {
}

func writeUint64MetricCounterHeader(buf *strings.Builder, name string, desc string) {
	buf.WriteString("# HELP ")
	buf.WriteString(name)
	buf.WriteString(" ")
	buf.WriteString(desc)
	buf.WriteString("\n# TYPE ")
	buf.WriteString(name)
	buf.WriteString(" counter\n")
}

func writeUint64MetricValue(buf *strings.Builder, name string, labels string, value uint64) {
	buf.WriteString(name)
	if len(labels) > 0 {
		buf.WriteString("{" + labels + "}")
	}
	buf.WriteString(" ")
	buf.WriteString(strconv.FormatUint(value, 10))
	buf.WriteString("\n")
}

// WriteMetric writes the netdev metrics to the provided buffer.
func (pg netDevGatherer) WriteMetric(buf *strings.Builder, parentLabels string) {
	nds, err := getNetDevStats()
	if err != nil {
		return
	}
	var sep string
	if len(parentLabels) > 0 {
		sep = ","
	}

	writeUint64MetricCounterHeader(buf, "algod_netdev_received_bytes", "Bytes received")
	for _, nd := range nds {
		labels := fmt.Sprintf("iface=\"%s\"%s%s", nd.iface, sep, parentLabels)
		writeUint64MetricValue(buf, "algod_netdev_received_bytes", labels, nd.bytesReceived)
	}

	writeUint64MetricCounterHeader(buf, "algod_netdev_sent_bytes", "Bytes sent")
	for _, nd := range nds {
		labels := fmt.Sprintf("iface=\"%s\"%s%s", nd.iface, sep, parentLabels)
		writeUint64MetricValue(buf, "algod_netdev_sent_bytes", labels, nd.bytesSent)
	}
}

// AddMetric writes the netdev metrics to the provided map.
func (pg netDevGatherer) AddMetric(values map[string]float64) {
	nds, err := getNetDevStats()
	if err != nil {
		return
	}
	for _, nd := range nds {
		values[sanitizeTelemetryName("algod_netdev_received_bytes_"+nd.iface)] = float64(nd.bytesReceived)
		values[sanitizeTelemetryName("algod_netdev_sent_bytes_"+nd.iface)] = float64(nd.bytesSent)
	}
}
