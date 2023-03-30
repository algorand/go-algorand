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

package stateproof

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/stateproofmsg"
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
	createBuildersTable = `CREATE TABLE IF NOT EXISTS builders (
    	round INTEGER PRIMARY KEY NOT NULL,
    	builder BLOB NOT NULL
    )`

	insertOrReplaceBuilderForRound = `INSERT OR REPLACE INTO builders (round,builder) VALUES (?,?)`

	selectBuilderForRound = `SELECT builder FROM builders WHERE round=?`

	deleteBuilderForRound = `DELETE FROM builders WHERE round<?`
)

// dbSchemaUpgrade0 initialize the tables.
func dbSchemaUpgrade0(_ context.Context, tx *sql.Tx, _ bool) error {
	_, err := tx.Exec(createSigsTable)
	if err != nil {
		return err
	}

	_, err = tx.Exec(createSigsIdx)

	return err
}

func dbSchemaUpgrade1(_ context.Context, tx *sql.Tx, _ bool) error {
	_, err := tx.Exec(createBuildersTable)

	return err
}

func makeStateProofDB(accessor db.Accessor) error {
	migrations := []db.Migration{
		dbSchemaUpgrade0,
		dbSchemaUpgrade1,
	}

	err := db.Initialize(accessor, migrations)
	if err != nil {
		return fmt.Errorf("unable to initialize participation registry database: %w", err)
	}

	return nil
}

//#region Sig Operations

type pendingSig struct {
	signer       basics.Address
	sig          merklesignature.Signature
	fromThisNode bool
}

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

// Returns pending sigs up to the threshold round.
// The highest round sigs (which might be higher than the threshold) is also included.
func getPendingSigs(tx *sql.Tx, threshold basics.Round, maxRound basics.Round, onlyFromThisNode bool) (map[basics.Round][]pendingSig, error) {
	query := "SELECT sprnd, signer, sig, from_this_node FROM sigs WHERE (sprnd<=? OR sprnd=?)"
	if onlyFromThisNode {
		query += " AND from_this_node=1"
	}

	rows, err := tx.Query(query, threshold, maxRound)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return rowsToPendingSigs(rows)
}

func getPendingSigsForRound(tx *sql.Tx, rnd basics.Round) ([]pendingSig, error) {
	rows, err := tx.Query("SELECT sprnd, signer, sig, from_this_node FROM sigs WHERE sprnd=?", rnd)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tmpmap, err := rowsToPendingSigs(rows)
	if err != nil {
		return nil, err
	}
	return tmpmap[rnd], nil
}

func sigExistsInDB(tx *sql.Tx, rnd basics.Round, account Address) (bool, error) {
	row := tx.QueryRow("SELECT EXISTS ( SELECT 1 FROM sigs WHERE signer=? AND sprnd=?)", account[:], rnd)

	exists := 0
	if err := row.Scan(&exists); err != nil {
		return false, err
	}

	return exists != 0, nil
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
func persistBuilder(tx *sql.Tx, rnd basics.Round, b *builder) error {
	_, err := tx.Exec(insertOrReplaceBuilderForRound, rnd, protocol.Encode(b))
	return err
}

func getBuilder(tx *sql.Tx, rnd basics.Round) (builder, error) {
	row := tx.QueryRow(selectBuilderForRound, rnd)
	var rawBuilder []byte
	err := row.Scan(&rawBuilder)
	if err != nil {
		return builder{}, fmt.Errorf("getBuilder: builder for round %d not found in the database: %w", rnd, err)
	}
	var bldr builder
	err = protocol.Decode(rawBuilder, &bldr)
	if err != nil {
		return builder{}, fmt.Errorf("getBuilder: getBuilder: builder for round %d failed to decode: %w", rnd, err)
	}

	// Stored Builder is corrupted...
	if bldr.Builder == nil {
		return builder{}, fmt.Errorf("getBuilder: builder for round %d is corrupted", rnd)
	}

	bldr.Builder.AllocSigs()

	return bldr, nil
}

// This function is used to fetch only the StateProof Message from within the builder stored on disk.
// In the future, StateProof messages should perhaps be stored in their own table and this implementation will change.
func getMessage(tx *sql.Tx, rnd basics.Round) (stateproofmsg.Message, error) {
	row := tx.QueryRow(selectBuilderForRound, rnd)
	var rawBuilder []byte
	err := row.Scan(&rawBuilder)
	if err != nil {
		return stateproofmsg.Message{}, fmt.Errorf("getMessage: builder for round %d not found in the database: %w", rnd, err)
	}
	var bldr builder
	err = protocol.Decode(rawBuilder, &bldr)
	if err != nil {
		return stateproofmsg.Message{}, fmt.Errorf("getMessage: builder for round %d failed to decode: %w", rnd, err)
	}

	return bldr.Message, nil
}

func builderExistInDB(tx *sql.Tx, rnd basics.Round) (bool, error) {
	row := tx.QueryRow("SELECT EXISTS ( SELECT 1 FROM builders WHERE round=? )", rnd)

	exists := 0
	if err := row.Scan(&exists); err != nil {
		return false, err
	}

	return exists != 0, nil
}

// deleteBuilders deletes all builders before (but not including) the given rnd
func deleteBuilders(tx *sql.Tx, rnd basics.Round) error {
	_, err := tx.Exec(deleteBuilderForRound, rnd)
	return err
}

func getSignatureRounds(tx *sql.Tx, threshold basics.Round, maxRound basics.Round) ([]basics.Round, error) {
	var rnds []basics.Round
	rows, err := tx.Query("SELECT DISTINCT sprnd FROM sigs WHERE (sprnd<=? OR sprnd=?)", threshold, maxRound)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rnd basics.Round
	for rows.Next() {
		err := rows.Scan(&rnd)
		if err != nil {
			return nil, err
		}
		rnds = append(rnds, rnd)
	}
	return rnds, nil
}

//#endregion
