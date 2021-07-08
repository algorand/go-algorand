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

package account

//go:generate dbgen -i root.sql -p account -n root -o rootInstall.go -h ../../scripts/LICENSE_HEADER
import (
	"context"
	"database/sql"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// A Root encapsulates a set of secrets which controls some store of money.
//
// A Root is authorized to spend money and create Participations
// for which this account is the parent.
//
// It handles persistence and secure deletion of secrets.
type Root struct {
	secrets *crypto.SignatureSecrets

	store db.Accessor
}

// GenerateRoot uses the system's source of randomness to generate an
// account.
func GenerateRoot(store db.Accessor) (Root, error) {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	return ImportRoot(store, seed)
}

// ImportRoot uses a provided source of randomness to instantiate an
// account.
func ImportRoot(store db.Accessor, seed [32]byte) (acc Root, err error) {
	s := crypto.GenerateSignatureSecrets(seed)
	raw := protocol.Encode(s)

	err = store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		err := rootInstallDatabase(tx)
		if err != nil {
			return fmt.Errorf("ImportRoot: failed to install database: %v", err)
		}

		stmt, err := tx.Prepare("insert into RootAccount values (?)")
		if err != nil {
			return fmt.Errorf("ImportRoot: failed to prepare statement: %v", err)
		}

		_, err = stmt.Exec(raw)
		if err != nil {
			return fmt.Errorf("ImportRoot: failed to insert account: %v", err)
		}

		return nil
	})

	if err != nil {
		return
	}

	acc.secrets = s
	acc.store = store
	return
}

// RestoreRoot restores a Root from a database handle.
func RestoreRoot(store db.Accessor) (acc Root, err error) {
	var raw []byte

	err = store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var nrows int
		row := tx.QueryRow("select count(*) from RootAccount")
		err := row.Scan(&nrows)
		if err != nil {
			return fmt.Errorf("RestoreRoot: could not query storage: %v", err)
		}
		if nrows != 1 {
			logging.Base().Infof("RestoreRoot: state not found (n = %v)", nrows)
		}

		row = tx.QueryRow("select data from RootAccount")
		err = row.Scan(&raw)
		if err != nil {
			return fmt.Errorf("RestoreRoot: could not read account raw data: %v", err)
		}

		return nil
	})

	if err != nil {
		return
	}

	acc.secrets = &crypto.SignatureSecrets{}
	err = protocol.Decode(raw, acc.secrets)
	if err != nil {
		err = fmt.Errorf("RestoreRoot: error decoding account: %v", err)
		return
	}

	acc.store = store
	return
}

// Secrets returns the signing secrets associated with the Root account.
func (root Root) Secrets() *crypto.SignatureSecrets {
	return root.secrets
}

// Address returns the address associated with the Root account.
func (root Root) Address() basics.Address {
	return basics.Address(root.secrets.SignatureVerifier)
}

// RestoreParticipation restores a Participation from a database
// handle.
func RestoreParticipation(store db.Accessor) (acc PersistedParticipation, err error) {
	var rawParent, rawVRF, rawVoting, rawCompactCert []byte

	err = Migrate(store)
	if err != nil {
		return
	}

	err = store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var nrows int
		row := tx.QueryRow("select count(*) from ParticipationAccount")
		err := row.Scan(&nrows)
		if err != nil {
			return fmt.Errorf("RestoreParticipation: could not query storage: %v", err)
		}
		if nrows != 1 {
			logging.Base().Infof("RestoreParticipation: state not found (n = %v)", nrows)
		}

		row = tx.QueryRow("select parent, vrf, voting,compactCert, firstValid, lastValid, keyDilution from ParticipationAccount")

		err = row.Scan(&rawParent, &rawVRF, &rawVoting, &rawCompactCert, &acc.FirstValid, &acc.LastValid, &acc.KeyDilution)
		if err != nil {
			return fmt.Errorf("RestoreParticipation: could not read account raw data: %v", err)
		}

		copy(acc.Parent[:32], rawParent)
		return nil
	})
	if err != nil {
		return PersistedParticipation{}, err
	}

	acc.Store = store

	acc.VRF = &crypto.VRFSecrets{}
	err = protocol.Decode(rawVRF, acc.VRF)
	if err != nil {
		return PersistedParticipation{}, err
	}

	acc.Voting = &crypto.OneTimeSignatureSecrets{}
	err = protocol.Decode(rawVoting, acc.Voting)
	if err != nil {
		return PersistedParticipation{}, err
	}

	// nothing is stored in the rawCompactCertKey
	if len(rawCompactCert) == 0 {
		return acc, nil
	}
	acc.CompactCertKey = &crypto.SignatureAlgorithm{}
	if err = protocol.Decode(rawCompactCert, acc.CompactCertKey); err != nil {
		return PersistedParticipation{}, err
	}
	// rawCompactCertKey was stored as not valid.
	if !acc.CompactCertKey.IsValid() {
		return PersistedParticipation{}, fmt.Errorf("stored compact certificate key is not valid")
	}

	return acc, nil
}
