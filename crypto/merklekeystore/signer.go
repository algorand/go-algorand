package merklekeystore

import (
	"fmt"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
)

type disposableKeys []*crypto.SignatureAlgorithm

//Length returns the amount of disposable keys
func (d disposableKeys) Length() uint64 {
	return uint64(len(d))
}

// GetHash Gets the hash of the VerifyingKey tied to the signatureAlgorithm in pos.
func (d disposableKeys) GetHash(pos uint64) (crypto.Digest, error) {
	return disposableKeyHash(d[pos])
}

func disposableKeyHash(s *crypto.SignatureAlgorithm) (crypto.Digest, error) {
	vkey := s.GetSigner().GetVerifyingKey()
	return crypto.HashObj(&vkey), nil
}

// Signature is a byte signature on a crypto.Hashable object, and includes a merkle proof for the signing key.
type Signature struct {
	crypto.ByteSignature
	Proof []crypto.Digest
	*crypto.VerifyingKey
	// the lead position of the VerifyingKey
	pos uint64
}

type Signer struct {
	root crypto.Digest
	// these keys are the keys used to sign in a round.
	// should be disposed of once possible.
	disposableKeys
	startRound uint64
	tree       *merklearray.Tree
}

var errStartBiggerThanEndRound = fmt.Errorf("cannot create merkleKeyStore because end round is smaller then start round")

func New(startRound, endRound uint64) (*Signer, error) {
	if startRound > endRound {
		return nil, errStartBiggerThanEndRound
	}
	keys := make(disposableKeys, endRound-startRound)
	for i := range keys {
		keys[i] = crypto.NewSigner(crypto.PlaceHolderType)
	}
	tree, err := merklearray.Build(keys)
	if err != nil {
		return nil, err
	}

	return &Signer{
		root:           tree.Root(),
		disposableKeys: keys,
		startRound:     startRound,
		tree:           tree,
	}, nil
}

func (m *Signer) GetVerifier() *verifier {
	return &verifier{
		root: m.root,
	}
}

// Sign outputs a signature + proof for the signing key.
func (m *Signer) Sign(hashable crypto.Hashable, round int) (Signature, error) {
	pos, err := m.getKeyPosition(uint64(round))
	if err != nil {
		return Signature{}, err
	}

	// should never happen:
	proof, err := m.tree.Prove([]uint64{pos})
	if err != nil {
		return Signature{}, err
	}

	signer := m.disposableKeys[pos].GetSigner()
	vkey := signer.GetVerifyingKey()
	return Signature{
		ByteSignature: signer.Sign(hashable),
		Proof:         proof,
		VerifyingKey:  &vkey,
		pos:           pos,
	}, nil
}

var errOutOfBounds = fmt.Errorf("cannot find signing key for given round")

func (m *Signer) getKeyPosition(round uint64) (uint64, error) {
	if round < m.startRound {
		return 0, errOutOfBounds
	}

	pos := round - m.startRound
	if pos >= uint64(len(m.disposableKeys)) {
		return 0, errOutOfBounds
	}
	return pos, nil
}
