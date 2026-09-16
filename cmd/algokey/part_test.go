// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package main

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

// makeV3PartkeyFile creates a version 3 participation key file, as an old
// algokey would have written it, and returns the key.  With nullStateProof
// the stateProof column is NULL (a v3 file upgraded from v1/v2 by old code).
func makeV3PartkeyFile(t *testing.T, keyfile string, nullStateProof bool) account.Participation {
	t.Helper()
	a := require.New(t)

	const first, last, dilution = 1, 200, 10
	firstID := basics.OneTimeIDForRound(first, dilution)
	lastID := basics.OneTimeIDForRound(last, dilution)
	votingSecrets := crypto.GenerateOneTimeSignatureSecrets(firstID.Batch, lastID.Batch-firstID.Batch+1)
	// make the key mid-life so both batch and offset subkeys exist
	votingSecrets.DeleteBeforeFineGrained(basics.OneTimeIDForRound(42, dilution), dilution)

	part := account.Participation{
		FirstValid:  first,
		LastValid:   last,
		KeyDilution: dilution,
		Voting:      votingSecrets,
		VRF:         crypto.GenerateVRFSecrets(),
	}
	crypto.RandBytes(part.Parent[:])
	if !nullStateProof {
		stateProofSecrets, err := merklesignature.New(first, last, (last+1)/2)
		a.NoError(err)
		part.StateProofSecrets = stateProofSecrets
	}

	voting := part.Voting.Snapshot()
	rawVoting := protocol.Encode(&voting)

	partdb, err := db.MakeErasableAccessor(keyfile)
	a.NoError(err)
	defer partdb.Close()

	err = partdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.Exec(`CREATE TABLE schema (tablename TEXT PRIMARY KEY, version INTEGER);`); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO schema (tablename, version) VALUES (?, ?)", account.PartTableSchemaName, account.PartTableSchemaVersionVotingSplit-1); err != nil {
			return err
		}
		if _, err := tx.Exec(`CREATE TABLE ParticipationAccount (
			parent BLOB, vrf BLOB, voting BLOB,
			firstValid INTEGER, lastValid INTEGER,
			keyDilution INTEGER NOT NULL DEFAULT 0, stateProof BLOB);`); err != nil {
			return err
		}
		var rawStateProof []byte
		if part.StateProofSecrets != nil {
			rawStateProof = protocol.Encode(&part.StateProofSecrets.SignerContext)
		}
		_, err := tx.Exec("INSERT INTO ParticipationAccount (parent, vrf, voting, firstValid, lastValid, keyDilution, stateProof) VALUES (?, ?, ?, ?, ?, ?, ?)",
			part.Parent[:], protocol.Encode(part.VRF), rawVoting, part.FirstValid, part.LastValid, part.KeyDilution,
			rawStateProof)
		return err
	})
	a.NoError(err)

	// real v3 files carry the state proof secret keys in their own table
	if part.StateProofSecrets != nil {
		a.NoError(part.StateProofSecrets.Persist(partdb))
	}
	return part
}

func partkeyFileVersion(a *require.Assertions, keyfile string) int {
	partdb, err := db.MakeErasableAccessor(keyfile)
	a.NoError(err)
	defer partdb.Close()
	version, err := account.PartkeySchemaVersion(partdb)
	a.NoError(err)
	return version
}

// TestPartMigrate covers `algokey part migrate`: a v3 file (with and without
// state proof keys) is migrated into an untouched-original `.new` copy at the
// latest version and validated against it, and an existing `.new` is refused.
func TestPartMigrate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, nullStateProof := range []bool{false, true} {
		name := "withStateProof"
		if nullStateProof {
			name = "nullStateProof"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := require.New(t)

			keyfile := filepath.Join(t.TempDir(), "test.partkey")
			original := makeV3PartkeyFile(t, keyfile, nullStateProof)
			bytesBefore, err := os.ReadFile(keyfile)
			a.NoError(err)

			var out bytes.Buffer
			partkey, migrated, err := runPartMigrate(keyfile, false, &out)
			a.NoError(err)
			a.True(migrated)
			a.Contains(out.String(), "Migrated")
			a.Contains(out.String(), "Validation PASSED")

			// original untouched (validation read it without migrating), the
			// .new copy is at the latest version and matches the original
			bytesAfter, err := os.ReadFile(keyfile)
			a.NoError(err)
			a.Equal(bytesBefore, bytesAfter)
			a.Equal(account.PartTableSchemaVersionVotingSplit-1, partkeyFileVersion(a, keyfile))
			a.Equal(account.PartTableSchemaVersion, partkeyFileVersion(a, keyfile+".new"))
			a.NoError(comparePartkeys(original, partkey))
			a.Equal(nullStateProof, partkey.StateProofSecrets == nil)
		})
	}

	t.Run("existingNewRefused", func(t *testing.T) {
		t.Parallel()
		a := require.New(t)

		keyfile := filepath.Join(t.TempDir(), "test.partkey")
		makeV3PartkeyFile(t, keyfile, false)
		a.NoError(os.WriteFile(keyfile+".new", []byte("occupied"), 0600))

		var out bytes.Buffer
		_, _, err := runPartMigrate(keyfile, false, &out)
		a.ErrorContains(err, "already exists")
	})
}

// TestComparePartkeys covers the validation comparator: whole-key and
// metadata mismatches, and a copy whose state proof secret keys are missing
// (the Participation encoding itself covers only the SignerContext).
func TestComparePartkeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	dir := t.TempDir()
	p1 := makeV3PartkeyFile(t, filepath.Join(dir, "a.partkey"), false)
	p2 := makeV3PartkeyFile(t, filepath.Join(dir, "b.partkey"), false)

	a.NoError(comparePartkeys(p1, p1))
	a.Error(comparePartkeys(p1, p2))

	tweaked := p1
	tweaked.KeyDilution++
	a.ErrorContains(comparePartkeys(p1, tweaked), "metadata")

	// state proof secret keys live in their own table and are compared only
	// when loaded; a copy missing them must be detected
	partdb, err := db.MakeErasableAccessor(filepath.Join(dir, "a.partkey"))
	a.NoError(err)
	defer partdb.Close()

	withKeys, err := account.RestoreParticipationUnmigrated(partdb)
	a.NoError(err)
	a.NoError(withKeys.StateProofSecrets.RestoreAllSecrets(partdb))
	a.NotEmpty(withKeys.StateProofSecrets.GetAllKeys())

	withoutKeys, err := account.RestoreParticipationUnmigrated(partdb)
	a.NoError(err)
	a.Empty(withoutKeys.StateProofSecrets.GetAllKeys())

	a.ErrorContains(comparePartkeys(withKeys.Participation, withoutKeys.Participation), "state proof key count mismatch")
}
