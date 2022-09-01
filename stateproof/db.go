// Copyright (C) 2019-2022 Algorand, Inc.
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

package stateproof

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

const (
	// sigs tracks signatures used to build a state proofs, for
	// rounds that have not formed a state proofs yet.
	//
	// There can be at most one signature for a given (sprnd, signer):
	// that is, a signer (account address) can produce at most one signature
	// for a given sprnd (the round of the block being signed).
	//
	// Signatures produced by this node are special because we broadcast
	// them early; other signatures are retransmitted later on.
	createSigsTable = `CREATE TABLE IF NOT EXISTS sigs (
		sprnd integer,
		signer blob,
		sig blob,
		from_this_node integer,
		UNIQUE (sprnd, signer))`

	createSigsIdx = `CREATE INDEX IF NOT EXISTS sigs_from_this_node ON sigs (from_this_node)`

	// builders table stored a serialization of each BuilderForRound data, without the sigs (stored separately)
	// This table is only used when the TODO flag is specified in startup (relay nodes only)
	createBuildersTable = `CREATE TABLE IF NOT EXISTS builders (
    	round INTEGER PRIMARY KEY NOT NULL,
    	builder BLOB NOT NULL
    )`

	insertBuilderForRound = `INSERT INTO builders (round,builder) VALUES (?,?)`

	selectBuilderForRound = `SELECT builder FROM builders WHERE round=?`
)

// dbSchemaUpgrade0 initialize the tables.
func dbSchemaUpgrade0(_ context.Context, tx *sql.Tx, _ bool) error {
	_, err := tx.Exec(createSigsTable)
	if err != nil {
		return err
	}

	_, err = tx.Exec(createSigsIdx)
	if err != nil {
		return err
	}

	_, err = tx.Exec(createBuildersTable)
	if err != nil {
		return err
	}

	return nil
}

type pendingSig struct {
	signer       basics.Address
	sig          merklesignature.Signature
	fromThisNode bool
}

func makeStateProofDB(accessor db.Accessor) error {
	migrations := []db.Migration{
		dbSchemaUpgrade0,
	}

	err := db.Initialize(accessor, migrations)
	if err != nil {
		accessor.Close()
		return fmt.Errorf("unable to initialize participation registry database: %w", err)
	}

	return nil
}

//#region Sig Operations
func addPendingSig(tx *sql.Tx, rnd basics.Round, psig pendingSig) error {
	_, err := tx.Exec("INSERT INTO sigs (sprnd, signer, sig, from_this_node) VALUES (?, ?, ?, ?)",
		rnd,
		psig.signer[:],
		protocol.Encode(&psig.sig),
		psig.fromThisNode)
	return err
}

func deletePendingSigsBeforeRound(tx *sql.Tx, rnd basics.Round) error {
	_, err := tx.Exec("DELETE FROM sigs WHERE sprnd<?", rnd)
	return err
}

func getPendingSigs(tx *sql.Tx) (map[basics.Round][]pendingSig, error) {
	rows, err := tx.Query("SELECT sprnd, signer, sig, from_this_node FROM sigs")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return rowsToPendingSigs(rows)
}

func getPendingSigsFromThisNode(tx *sql.Tx) (map[basics.Round][]pendingSig, error) {
	rows, err := tx.Query("SELECT sprnd, signer, sig, from_this_node FROM sigs WHERE from_this_node=1")
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

//#endregion

//#region Builders Operations
func insertBuilder(tx *sql.Tx, rnd basics.Round, b *builder) error {
	_, err := tx.Exec(insertBuilderForRound, rnd, protocol.Encode(b))
	return err
}

func getBuilder(tx *sql.Tx, rnd basics.Round) (*builder, error) {
	var b builder
	row := tx.QueryRow(selectBuilderForRound, rnd)
	err := row.Scan(&b)
	if err != nil {
		return &builder{}, fmt.Errorf("getBuilder: builder for round %d not found in database: %w", rnd, err)
	}

	return &b, nil
}

//#endregion
