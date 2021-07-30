package node

import (
	"fmt"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/util/db"
)

type ParticipationID crypto.Digest

type ParticipationRecord struct {
	ParticipationID ParticipationID
	Account basics.Address
	FirstValid basics.Round
	LastValid basics.Round
	KeyDilution uint64

	LastVote basics.Round
	LastBlockProposal basics.Round
	LastCompactCertificate basics.Round
	EffectiveFirst basics.Round
	EffectiveLast basics.Round

	// VRFSecrets
	// OneTimeSignatureSecrets
}

var ParticipationIDNotFoundErr error

func init() {
	ParticipationIDNotFoundErr = fmt.Errorf("the participation ID was not found")
}

type ParticipationStorage interface {
	// Insert adds a record to storage and computes the ParticipationID
	Insert(record ParticipationRecord) (ParticipationID, error)

	// Delete removes a record from storage.
	Delete(id ParticipationID) error

	// Register updates the EffectiveFirst and EffectiveLast fields. If there are multiple records for the account
	// then it is possible for multiple records to be updated.
	Register(id ParticipationID, on basics.Round) error

	// RecordVote sets the LastVote field for the ParticipationID.
	RecordVote(id ParticipationID, round basics.Round) error

	// RecordBlockProposal sets the LastBlockProposal field for the ParticipationID.
	RecordBlockProposal(participationID ParticipationID, round basics.Round) error

	// RecordCompactCertificate sets the LastCompactCertificate field for the ParticipationID.
	RecordCompactCertificate(participationID ParticipationID, round basics.Round) error
}

func MakeParticipationStorage(db db.Accessor) ParticipationStorage {
	return &participationDB{
		store: db,
	}
}

type participationDB struct {
	store db.Accessor
}

func (db *participationDB) Insert(record ParticipationRecord) (ParticipationID, error) {
	return ParticipationID{}, nil
}

func (db *participationDB) Delete(id ParticipationID) error {
	return nil
}

func (db *participationDB) Register(id ParticipationID, on basics.Round) error {
	return nil
}

func (db *participationDB) RecordVote(id ParticipationID, round basics.Round) error {
	return nil
}

func (db *participationDB) RecordBlockProposal(participationID ParticipationID, round basics.Round) error {
	return nil
}

func (db *participationDB) RecordCompactCertificate(participationID ParticipationID, round basics.Round) error {
	return nil
}
