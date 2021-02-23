// Copyright (C) 2019-2021 Algorand, Inc.
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

package agreement

import (
	"context"
	"errors"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/protocol"
)

// this file holds abstractions that agreement depends on

// An BlockValidator validates that a given Block may correctly be appended to
// the sequence of Entries agreed upon by the protocol so far.
type BlockValidator interface {
	// Validate must return an error if a given Block cannot be determined
	// to be valid as applied to the agreement state; otherwise, it returns
	// nil.
	//
	// The correctness of Validate is essential to the correctness of the
	// protocol. If Validate accepts an invalid Block (i.e., a false
	// positive), the agreement protocol may fork, or the system state may
	// even become undefined. If Validate rejects a valid Block (i.e., a
	// false negative), the agreement protocol may even lose
	// liveness. Validate should therefore be conservative in which Entries
	// it accepts.
	//
	// TODO There should probably be a second Round argument here.
	Validate(context.Context, bookkeeping.Block) (ValidatedBlock, error)
}

// A ValidatedBlock represents an Block that has been successfuly validated
// and can now be recorded in the ledger.  This is an optimized version of
// calling EnsureBlock() on the Ledger.
type ValidatedBlock interface {
	// WithSeed creates a copy of this ValidatedBlock with its
	// cryptographically random seed set to the given value.
	//
	// Calls to Seed() or to Digest() on the copy's Block must
	// reflect the value of the new seed.
	WithSeed(committee.Seed) ValidatedBlock

	// Block returns the underlying block that has been validated.
	Block() bookkeeping.Block
}

// ErrAssembleBlockRoundStale is returned by AssembleBlock when the requested round number is not the
// one that matches the ledger last committed round + 1.
var ErrAssembleBlockRoundStale = errors.New("requested round for AssembleBlock is stale")

// An BlockFactory produces an Block which is suitable for proposal for a given
// Round.
type BlockFactory interface {
	// AssembleBlock produces a new ValidatedBlock which is suitable for proposal
	// at a given Round.  The time argument specifies a target deadline by
	// which the block should be produced.  Specifically, the deadline can
	// cause the factory to add fewer transactions to the block in question
	// than might otherwise be possible.
	//
	// AssembleBlock should produce a ValidatedBlock for which the corresponding
	// BlockValidator validates (i.e. for which BlockValidator.Validate
	// returns true). If an insufficient number of nodes can assemble valid
	// entries, the agreement protocol may lose liveness.
	//
	// AssembleBlock may return an error if the BlockFactory is unable to
	// produce a ValidatedBlock for the given round. If an insufficient number of
	// nodes on the network can assemble entries, the agreement protocol may
	// lose liveness.
	AssembleBlock(basics.Round, time.Time) (ValidatedBlock, error)
}

// A Ledger represents the sequence of Entries agreed upon by the protocol.
// The Ledger consists of two parts: a LedgerReader and a LedgerWriter, which
// provide read and write access to the ledger, respectively.
//
// Ledger must be safe for concurrent use.
//
// Once a method of Ledger succeeds, it must always succeed and become
// idempotent. (That is, all future calls to that method must return the same
// result, and multiple calls to a method must produce the same state as a
// single call.)
type Ledger interface {
	LedgerReader
	LedgerWriter
}

// A LedgerReader provides read access to observe the state of the ledger.
type LedgerReader interface {
	// NextRound returns the first round for which no Block has been
	// confirmed.
	NextRound() basics.Round

	// Wait returns a channel which fires when the specified round
	// completes and is durably stored on disk.
	Wait(basics.Round) chan struct{}

	// Seed returns the VRF seed that was agreed upon in a given round.
	//
	// The Seed is a source of cryptographic entropy which has bounded
	// bias. It is used to select committees for participation in
	// sortition.
	//
	// This method returns an error if the given Round has not yet been
	// confirmed. It may also return an error if the given Round is
	// unavailable by the storage device. In that case, the agreement
	// protocol may lose liveness.
	Seed(basics.Round) (committee.Seed, error)

	// Lookup returns the AccountData associated with some Address
	// at the conclusion of a given round.
	//
	// This method returns an error if the given Round has not yet been
	// confirmed. It may also return an error if the given Round is
	// unavailable by the storage device. In that case, the agreement
	// protocol may lose liveness.
	Lookup(basics.Round, basics.Address) (basics.AccountData, error)

	// Circulation returns the total amount of money in circulation at the
	// conclusion of a given round.
	//
	// This method returns an error if the given Round has not yet been
	// confirmed. It may also return an error if the given Round is
	// unavailable by the storage device. In that case, the agreement
	// protocol may lose liveness.
	Circulation(basics.Round) (basics.MicroAlgos, error)

	// TotalStake returns the total amount of accounts stake at the conclusion of a
	// given round.
	//
	// This method returns an error if the given Round has not yet been
	// confirmed. It may also return an error if the given Round is
	// unavailable by the storage device. In that case, the agreement
	// protocol may lose liveness.
	TotalStake(basics.Round) (basics.MicroAlgos, error)

	// LookupDigest returns the Digest of the entry that was agreed on in a
	// given round.
	//
	// Recent Entry Digests are periodically used when computing the Seed.
	// This prevents some subtle attacks.
	//
	// This method returns an error if the given Round has not yet been
	// confirmed. It may also return an error if the given Round is
	// unavailable by the storage device. In that case, the agreement
	// protocol may lose liveness.
	//
	// A LedgerReader need only keep track of the digest from the most
	// recent multiple of (config.Protocol.BalLookback/2). All other
	// digests may be forgotten without hurting liveness.
	LookupDigest(basics.Round) (crypto.Digest, error)

	// ConsensusParams returns the consensus parameters that are correct
	// for the given round.
	//
	// This method returns an error if the given Round has not yet been
	// confirmed. It may also return an error if the given Round is
	// unavailable by the storage device. In that case, the agreement
	// protocol may lose liveness.
	//
	// TODO replace with ConsensusVersion
	ConsensusParams(basics.Round) (config.ConsensusParams, error)

	// ConsensusVersion returns the consensus version that is correct
	// for the given round.
	//
	// This method returns an error if the given Round has not yet been
	// confirmed. It may also return an error if the given Round is
	// unavailable by the storage device. In that case, the agreement
	// protocol may lose liveness.
	ConsensusVersion(basics.Round) (protocol.ConsensusVersion, error)
}

// A LedgerWriter allows writing entries to the ledger.
type LedgerWriter interface {
	// EnsureBlock adds a Block, along with a Certificate authenticating
	// its contents, to the ledger.
	//
	// The Ledger must guarantee that after this method returns, any Seed,
	// Record, or Circulation call reflects the contents of this Block.
	//
	// EnsureBlock will never be called twice for two entries e1 and e2
	// where e1.Round() == e2.Round() but e1.Digest() != e2.Digest(). If
	// this is the case, the behavior of Ledger is undefined.
	// (Implementations are encouraged to panic or otherwise fail loudly in
	// this case, because it means that a fork has occurred.)
	//
	// EnsureBlock does not wait until the block is written to disk; use
	// Wait() for that.
	EnsureBlock(bookkeeping.Block, Certificate)

	// EnsureValidatedBlock is an optimized version of EnsureBlock that
	// works on a ValidatedBlock, but otherwise has the same semantics
	// as above.
	EnsureValidatedBlock(ValidatedBlock, Certificate)

	// EnsureDigest signals the Ledger to attempt to fetch a Block matching
	// the given Certificate.  EnsureDigest does not wait for the block to
	// be written to disk; use Wait() if needed.
	//
	// The Ledger must guarantee that after this method returns, any Seed,
	// Record, or Circulation call reflects the contents of the Block
	// authenticated by the given Certificate.
	//
	// EnsureDigest will never be called twice for two certificates c1 and
	// c2 where c1 authenticates the block e1 and c2 authenticates the block
	// e2, but e1.Round() == e2.Round() and e1.Digest() != e2.Digest(). If
	// this is the case, the behavior of Ledger is undefined.
	// (Implementations are encouraged to panic or otherwise fail loudly in
	// this case, because it means that a fork has occurred.)
	EnsureDigest(Certificate, *AsyncVoteVerifier)
}

// A KeyManager stores and deletes participation keys.
type KeyManager interface {
	// Keys returns an immutable array of participation intervals to
	// participating accounts.
	Keys() []account.Participation

	// HasLiveKeys returns true if we have any Participation
	// keys valid for the specified round range (inclusive)
	HasLiveKeys(from, to basics.Round) bool
}

// MessageHandle is an ID referring to a specific message.
//
// A MessageHandle of nil denotes that a message is "sourceless".
type MessageHandle interface{}

// Network is an abstraction over the interface expected by the agreement
// protocol.
type Network interface {
	// Messages returns a channel of Messages which corresponds to a given
	// protocol.Tag.
	Messages(protocol.Tag) <-chan Message

	// Broadcast attempts to send a slice of bytes under some protocol.Tag
	// to all neighbors.
	//
	// Broadcast represents a best-effort, ordered delivery mechanism.  In
	// other words, sends to any given peer may fail due to disconnection or
	// network congestion.  However, the Network should try to transmit
	// messages in the order identical to the ordering of Broadcast calls.
	//
	// Calls to Broadcast by the agreement package are currently guaranteed
	// to be serialized.
	//
	// If the broadcasting of the message have failed or is not possible, the
	// method returns a non-nil error describing the underlaying error.
	// otherwise, a nil is returned.
	Broadcast(protocol.Tag, []byte) error

	// Relay attempts to send a slice of bytes under some protocol.Tag to
	// all neighbors, except for the neighbor associated with the given
	// MessageHandle.
	//
	// The behavior of Relay is otherwise identical to Broadcast.
	//
	// Passing a MessageHandle value of nil to Relay should produce behavior
	// identical to calling Broadcast.  In other words, the calls
	// Broadcast(tag, data) and Relay(nil, tag, data) should cause identical
	// behavior.
	//
	// If the relaying of the message have failed or is not possible, the
	// method returns a non-nil error describing the underlaying error.
	// otherwise, a nil is returned.
	Relay(MessageHandle, protocol.Tag, []byte) error

	// Disconnect sends the Network a hint to disconnect to the peer
	// associated with the given MessageHandle.
	Disconnect(MessageHandle)

	// Start notifies the network that the agreement service is ready
	// to start receiving messages.
	Start()
}

// RandomSource is an abstraction over the random number generator.
// The agreement protocol use it to determine the duration of which
// different nodes would wait on steps 5 and above.
type RandomSource interface {
	// Uint64 returns a pseudo-random 64-bit value as a uint64.
	Uint64() uint64
}

// Message encapsulates a MessageHandle and its payload.
type Message struct {
	MessageHandle
	Data []byte
}

// EventsProcessingMonitor is an abstraction over the
// inner queues of the agreement service. It allows an external
// client to monitor the activity of the various events queues.
type EventsProcessingMonitor interface {
	UpdateEventsQueue(queueName string, queueLength int)
}

// LedgerDroppedRoundError is a wrapper error for when the ledger cannot return a Lookup query because
// the entry is old and was dropped from the ledger. The purpose of this wrapper is to help the
// agreement differentiate between a malicious vote and a vote that it cannot verify
type LedgerDroppedRoundError struct {
	Err error
}

func (e *LedgerDroppedRoundError) Error() string {
	return e.Err.Error()
}

func (e *LedgerDroppedRoundError) Unwrap() error {
	return e.Err
}
