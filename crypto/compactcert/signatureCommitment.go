package compactcert

import (
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

type commitableSignature struct {
	sigCommit           sigslotCommit
	serializedSignature []byte
}

type commitableSignatureArray []sigslot

func (sc commitableSignatureArray) Length() uint64 {
	return uint64(len(sc))
}

func (sc commitableSignatureArray) Marshal(pos uint64) ([]byte, error) {
	if pos >= uint64(len(sc)) {
		return nil, fmt.Errorf("pos %d past end %d", pos, len(sc))
	}

	signatureSlot, err := buildCommitableSignature(sc[pos].sigslotCommit)
	if err != nil {
		return nil, err
	}

	return crypto.HashRep(signatureSlot), nil

}

func buildCommitableSignature(sigCommit sigslotCommit) (*commitableSignature, error) {
	sigBytes, err := sigCommit.Sig.GetSerializedSignature()
	if err != nil {
		return nil, err
	}
	return &commitableSignature{sigCommit: sigCommit, serializedSignature: sigBytes}, nil
}

func (cs *commitableSignature) ToBeHashed() (protocol.HashID, []byte) {
	binaryLValue := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryLValue, cs.sigCommit.L)

	sigSlotCommitment := make([]byte, 0, len(binaryLValue)+len(cs.serializedSignature))
	sigSlotCommitment = append(sigSlotCommitment, binaryLValue...)
	sigSlotCommitment = append(sigSlotCommitment, cs.serializedSignature...)

	return protocol.CompactCertSig, sigSlotCommitment
}
