package v2

import (
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/labstack/echo/v4"

)

type V2Handlers struct {}

// Get account information.
// (GET /v2/accounts/{address})
func (v2 *V2Handlers) AccountInformation(ctx echo.Context, address string) error {
	return nil
}

// Get a list of unconfirmed transactions currently in the transaction pool by address.
// (GET /v2/accounts/{addr}/transactions/pending)
func (v2 *V2Handlers) GetPendingTransactionsByAddress(ctx echo.Context, addr string, params generated.GetPendingTransactionsByAddressParams) error {
	return nil
}

// Get the block for the given round.
// (GET /v2/blocks/{round})
func (v2 *V2Handlers) GetBlock(ctx echo.Context, round uint64, params generated.GetBlockParams) error {
	return nil
}

// Get the current supply reported by the ledger.
// (GET /v2/ledger/supply)
func (v2 *V2Handlers) GetSupply(ctx echo.Context) error {
	return nil
}

// (POST /v2/register-participation-keys/{account-id})
func (v2 *V2Handlers) PostV2RegisterParticipationKeysAccountId(ctx echo.Context, accountId string, params generated.PostV2RegisterParticipationKeysAccountIdParams) error {
	return nil
}

// (POST /v2/shutdown)
func (v2 *V2Handlers) PostV2Shutdown(ctx echo.Context, params generated.PostV2ShutdownParams) error {
	return nil
}

// Gets the current node status.
// (GET /v2/status)
func (v2 *V2Handlers) GetStatus(ctx echo.Context) error {
	return nil
}

// Gets the node status after waiting for the given round.
// (GET /v2/status/wait-for-block-after/{round}/)
func (v2 *V2Handlers) WaitForBlock(ctx echo.Context, round uint64) error {
	return nil
}

// Broadcasts a raw transaction to the network.
// (POST /v2/transactions)
func (v2 *V2Handlers) RawTransaction(ctx echo.Context) error {
	return nil
}

// Get parameters for constructing a new transaction
// (GET /v2/transactions/params)
func (v2 *V2Handlers) TransactionParams(ctx echo.Context) error {
	return nil
}

// Get a list of unconfirmed transactions currently in the transaction pool.
// (GET /v2/transactions/pending)
func (v2 *V2Handlers) GetPendingTransactions(ctx echo.Context, params generated.GetPendingTransactionsParams) error {
	return nil
}

// Get a specific pending transaction.
// (GET /v2/transactions/pending/{txid})
func (v2 *V2Handlers) PendingTransactionInformation(ctx echo.Context, txid string, params generated.PendingTransactionInformationParams) error {
	return nil
}

