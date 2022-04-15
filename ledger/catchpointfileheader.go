package ledger

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// CatchpointFileHeader is the content we would have in the "content.msgpack" file in the catchpoint tar archive.
// we need it to be public, as it's being decoded externally by the catchpointdump utility.
type CatchpointFileHeader struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Version           uint64                   `codec:"version"`
	BalancesRound     basics.Round             `codec:"balancesRound"`
	BlocksRound       basics.Round             `codec:"blocksRound"`
	Totals            ledgercore.AccountTotals `codec:"accountTotals"`
	TotalAccounts     uint64                   `codec:"accountsCount"`
	TotalChunks       uint64                   `codec:"chunksCount"`
	Catchpoint        string                   `codec:"catchpoint"`
	BlockHeaderDigest crypto.Digest            `codec:"blockHeaderDigest"`
}
