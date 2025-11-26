// Copyright (C) 2019-2025 Algorand, Inc.
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
	"github.com/algorand/go-algorand/crypto/merklesignature"
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
		err1 := rootInstallDatabase(tx)
		if err1 != nil {
			return fmt.Errorf("ImportRoot: failed to install database: %v", err1)
		}

		stmt, err1 := tx.Prepare("insert into RootAccount values (?)")
		if err1 != nil {
			return fmt.Errorf("ImportRoot: failed to prepare statement: %v", err1)
		}

		_, err1 = stmt.Exec(raw)
		if err1 != nil {
			return fmt.Errorf("ImportRoot: failed to insert account: %v", err1)
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
		err1 := row.Scan(&nrows)
		if err1 != nil {
			return fmt.Errorf("RestoreRoot: could not query storage: %v", err1)
		}
		if nrows != 1 {
			logging.Base().Infof("RestoreRoot: state not found (n = %v)", nrows)
		}

		row = tx.QueryRow("select data from RootAccount")
		err1 = row.Scan(&raw)
		if err1 != nil {
			return fmt.Errorf("RestoreRoot: could not read account raw data: %v", err1)
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
	var rawParent, rawVRF, rawVoting, rawStateProof []byte

	err = Migrate(store)
	if err != nil {
		return
	}

	err = store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var nrows int
		row := tx.QueryRow("select count(*) from ParticipationAccount")
		err1 := row.Scan(&nrows)
		if err1 != nil {
			return fmt.Errorf("RestoreParticipation: could not query storage: %v", err1)
		}
		if nrows != 1 {
			logging.Base().Infof("RestoreParticipation: state not found (n = %v)", nrows)
		}

		row = tx.QueryRow("select parent, vrf, voting, firstValid, lastValid, keyDilution, stateProof from ParticipationAccount")

		err1 = row.Scan(&rawParent, &rawVRF, &rawVoting, &acc.FirstValid, &acc.LastValid, &acc.KeyDilution, &rawStateProof)
		if err1 != nil {
			return fmt.Errorf("RestoreParticipation: could not read account raw data: %v", err1)
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

	if len(rawStateProof) == 0 {
		return acc, nil
	}
	acc.StateProofSecrets = &merklesignature.Secrets{}
	// only the state proof data is decoded here (the keys are stored in a different DB table and are fetched separately)
	if err = protocol.Decode(rawStateProof, acc.StateProofSecrets); err != nil {
		return PersistedParticipation{}, err
	}

	return acc, nil
}

// RestoreParticipationWithSecrets restores a Participation from a database
// handle. In addition, this function also restores all stateproof secrets
func RestoreParticipationWithSecrets(store db.Accessor) (PersistedParticipation, error) {
	persistedParticipation, err := RestoreParticipation(store)
	if err != nil {
		return PersistedParticipation{}, err
	}

	if persistedParticipation.StateProofSecrets == nil { // no state proof keys to restore
		return persistedParticipation, nil
	}

	err = persistedParticipation.StateProofSecrets.RestoreAllSecrets(store)
	if err != nil {
		return PersistedParticipation{}, err
	}
	return persistedParticipation, nil
}
