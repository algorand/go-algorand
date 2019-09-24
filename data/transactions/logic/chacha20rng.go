package logic

import (
	"encoding/binary"
	"errors"

	//"github.com/algobolson/chacha20"
	"gitlab.com/yawning/chacha20.git"
)

type ChaCha20RNG struct {
	cipher *chacha20.Cipher
}

// ErrInsufficientSeed seed arg too short
var ErrInsufficientSeed = errors.New("insufficient seed, need at least 32 bytes")

func NewChaCha20RNG(seed, more []byte) (rng *ChaCha20RNG, err error) {
	if len(seed) < chacha20.KeySize {
		return nil, ErrInsufficientSeed
	}
	if len(more) >= chacha20.XNonceSize {
		// 24
		more = more[:chacha20.XNonceSize]
	} else if len(more) >= chacha20.INonceSize {
		// 12
		more = more[:chacha20.INonceSize]
	} else if len(more) >= chacha20.NonceSize {
		// 8
		more = more[:chacha20.NonceSize]
	}
	c, err := chacha20.New(seed, more)
	if err != nil {
		return nil, err
	}
	return &ChaCha20RNG{cipher: c}, nil
}

func (cc *ChaCha20RNG) Uint64() uint64 {
	var b [8]byte
	cc.cipher.KeyStream(b[:])
	return binary.LittleEndian.Uint64(b[:])
}
