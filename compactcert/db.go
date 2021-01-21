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

package compactcert

import (
	"database/sql"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

var schema = []string{
	// sigs tracks signatures used to build a compact certificate, for
	// rounds that have not formed a compact certificate yet.
	//
	// There can be at most one signature for a given (certrnd, signer):
	// that is, a signer (account address) can produce at most one signature
	// for a given certrnd (the round of the block being signed).
	//
	// Signatures produced by this node are special because we broadcast
	// them early; other signatures are retransmitted later on.
	`CREATE TABLE IF NOT EXISTS sigs (
		certrnd integer,
		signer blob,
		sig blob,
		from_this_node integer,
		UNIQUE (certrnd, signer))`,

	`CREATE INDEX IF NOT EXISTS sigs_from_this_node ON sigs (from_this_node)`,
}

type pendingSig struct {
	signer       basics.Address
	sig          crypto.OneTimeSignature
	fromThisNode bool
}

func initDB(tx *sql.Tx) error {
	for i, tableCreate := range schema {
		_, err := tx.Exec(tableCreate)
		if err != nil {
			return fmt.Errorf("could not create compactcert table %d: %v", i, err)
		}
	}

	return nil
}

func addPendingSig(tx *sql.Tx, rnd basics.Round, psig pendingSig) error {
	_, err := tx.Exec("INSERT INTO sigs (certrnd, signer, sig, from_this_node) VALUES (?, ?, ?, ?)",
		rnd,
		psig.signer[:],
		protocol.Encode(&psig.sig),
		psig.fromThisNode)
	return err
}

func deletePendingSigsBeforeRound(tx *sql.Tx, rnd basics.Round) error {
	_, err := tx.Exec("DELETE FROM sigs WHERE certrnd<?", rnd)
	return err
}

func getPendingSigs(tx *sql.Tx) (map[basics.Round][]pendingSig, error) {
	rows, err := tx.Query("SELECT certrnd, signer, sig, from_this_node FROM sigs")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return rowsToPendingSigs(rows)
}

func getPendingSigsFromThisNode(tx *sql.Tx) (map[basics.Round][]pendingSig, error) {
	rows, err := tx.Query("SELECT certrnd, signer, sig, from_this_node FROM sigs WHERE from_this_node=1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return rowsToPendingSigs(rows)
}

func rowsToPendingSigs(rows *sql.Rows) (map[basics.Round][]pendingSig, error) {
	res := make(map[basics.Round][]pendingSig)
	for rows.Next() {
		var rnd basics.Round
		var signer []byte
		var sigbuf []byte
		var thisNode bool
		err := rows.Scan(&rnd, &signer, &sigbuf, &thisNode)
		if err != nil {
			return nil, err
		}

		var psig pendingSig
		copy(psig.signer[:], signer)
		psig.fromThisNode = thisNode
		err = protocol.Decode(sigbuf, &psig.sig)
		if err != nil {
			return nil, err
		}

		res[rnd] = append(res[rnd], psig)
	}

	return res, rows.Err()
}
