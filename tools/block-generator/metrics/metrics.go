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
