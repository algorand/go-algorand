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
	`CREATE TABLE IF NOT EXISTS sigs (
		certrnd integer,
		signer blob,
		sig blob,
		from_this_node integer)`,
	`CREATE TABLE IF NOT EXISTS signed_last (
		votingkey blob,
		rnd integer)`,
}

type pendingSig struct {
	signer       basics.Address
	sig          crypto.OneTimeSignature
	fromThisNode bool
}

func initDB(tx *sql.Tx) error {
	for _, tableCreate := range schema {
		_, err := tx.Exec(tableCreate)
		if err != nil {
			return fmt.Errorf("could not create table %v", err)
		}
	}

	return nil
}

func getSignedLast(tx *sql.Tx) ([]crypto.OneTimeSignatureVerifier, basics.Round, error) {
	rows, err := tx.Query("SELECT votingkey, rnd FROM signed_last")
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var res []crypto.OneTimeSignatureVerifier
	var maxRound basics.Round
	for rows.Next() {
		var rnd basics.Round
		var buf []byte
		err = rows.Scan(&rnd, &buf)
		if err != nil {
			return nil, 0, err
		}

		var votingkey crypto.OneTimeSignatureVerifier
		copy(votingkey[:], buf)
		res = append(res, votingkey)

		if rnd > maxRound {
			maxRound = rnd
		}
	}

	return res, maxRound, rows.Err()
}

func setSignedLast(tx *sql.Tx, rnd basics.Round, keys []crypto.OneTimeSignatureVerifier) error {
	_, err := tx.Exec("DELETE FROM signed_last")
	if err != nil {
		return err
	}

	for _, key := range keys {
		_, err = tx.Exec("INSERT INTO signed_last (votingkey, rnd) VALUES (?, ?)", key[:], rnd)
		if err != nil {
			return err
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

func deletePendingSigsUpToRound(tx *sql.Tx, rnd basics.Round) error {
	_, err := tx.Exec("DELETE FROM sigs WHERE certrnd<=?", rnd)
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
