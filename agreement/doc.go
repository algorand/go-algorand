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

// Package agreement implements Algorand's agreement protocol, which
// enables all nodes to consistently update the state of the system.
//
// The Service establishes a consensus on the ordering of
// Blocks. This ordering is defined by a Round number, which indexes
// into the ordered log of Blocks.
//
// Clients instantiate an Service by providing it several
// parameters:
//  - Ledger represents a data store which supports the reading and
//    writing of data stored within Blocks.
//  - BlockFactory produces Blocks for a given round.
//  - BlockValidator validates Blocks for a given round.
//  - KeyManager holds the participation keys necessary to participate
//    in the protocol.
//  - Network provides an abstraction over the underlying network.
//  - timers.Clock provides timekeeping services for timeouts.
//  - db.Accessor provides persistent storage for internal state.
//
//  Blocks for which consensus is completed are written using
//  Ledger.EnsureBlock alongside Certificate objects, which are
//  cryptographic proofs that a Block was confirmed for a given
//  round.
//
// If Ledger and db.Accessor provide crash-safe storage, agreement
// will also recover safely after crashes.
package agreement
