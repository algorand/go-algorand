package logic

import (
	"encoding/binary"
	"errors"

	"gitlab.com/yawning/chacha20.git"
)

// ChaCha20RNG uses ChaCha20 cryptographic byte sequence as a random number generator
type ChaCha20RNG struct {
	cipher *chacha20.Cipher
}

// ErrInsufficientSeed seed arg too short
var ErrInsufficientSeed = errors.New("insufficient seed, need at least 32 bytes")

// NewChaCha20RNG initializes ChaCha20 with a seed and extra nonce bytes.
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

// Uint64 returns 64 random bits
func (cc *ChaCha20RNG) Uint64() uint64 {
	var b [8]byte
	cc.cipher.KeyStream(b[:])
	return binary.LittleEndian.Uint64(b[:])
}
