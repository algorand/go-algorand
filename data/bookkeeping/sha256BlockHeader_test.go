package bookkeeping

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConvertSha256Header(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var gh crypto.Digest
	crypto.RandBytes(gh[:])

	var txnCommit TxnCommitments
	crypto.RandBytes(txnCommit.Sha256Commitment[:])
	blockHeader := BlockHeader{Round: 200, GenesisHash: gh, TxnCommitments: txnCommit}
	sha256Header := blockHeader.ToSha256BlockHeader()

	a.Equal(basics.Round(200), sha256Header.RoundNumber)
	a.Equal(txnCommit.Sha256Commitment[:], []byte(sha256Header.Sha256TxnCommitment))
	a.Equal(gh, sha256Header.GenesisHash)
}
