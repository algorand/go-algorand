// Copyright (C) 2019-2023 Algorand, Inc.
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

// Prometheus metrics collected in Conduit.
const (
	BlockImportTimeName      = "import_time_sec"
	ImportedTxnsPerBlockName = "imported_tx_per_block"
	ImportedRoundGaugeName   = "imported_round"
	GetAlgodRawBlockTimeName = "get_algod_raw_block_time_sec"
	ImportedTxnsName         = "imported_txns"
	ImporterTimeName         = "importer_time_sec"
	ProcessorTimeName        = "processor_time_sec"
	ExporterTimeName         = "exporter_time_sec"
	PipelineRetryCountName   = "pipeline_retry_count"
)

// AllMetricNames is a reference for all the custom metric names.
var AllMetricNames = []string{
	BlockImportTimeName,
	ImportedTxnsPerBlockName,
	ImportedRoundGaugeName,
	GetAlgodRawBlockTimeName,
	ImporterTimeName,
	ProcessorTimeName,
	ExporterTimeName,
	PipelineRetryCountName,
}
