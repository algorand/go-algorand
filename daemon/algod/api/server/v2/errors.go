package v2

var (
	errFailedLookingUpLedger               = "failed to retrieve information from the ledger"
	errFailedLookingUpTransactionPool      = "failed to retrieve information from the transaction pool"
	errFailedRetrievingNodeStatus          = "failed retrieving node status"
	errFailedParsingFormatOption           = "failed to parse the format option"
	errFailedToParseAddress                = "failed to parse the address"
	errFailedToParseTransaction            = "failed to parse transaction"
	errFailedToParseBlock                  = "failed to parse block"
	errInternalFailure                     = "internal failure"
	errNoTxnSpecified                      = "no transaction ID was specified"
	errTransactionNotFound                 = "couldn't find the required transaction in the required range"
	errServiceShuttingDown                 = "operation aborted as server is shutting down"
	errRequestedRoundInUnsupportedRound    = "requested round would reach only after the protocol upgrade which isn't supported"
)
