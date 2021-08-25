package crypto

// GenericDigest is used as the digest the tree will use.
//msgp:allocbound GenericDigest
type GenericDigest []byte

// To32Byte is used to change the data into crypto.Digest.
func (d GenericDigest) To32Byte() [32]byte {
	var cpy [32]byte
	copy(cpy[:], d)
	return cpy

}

// ToSlice is used inside the Tree itself when interacting with TreeDigest
func (d GenericDigest) ToSlice() []byte { return d }
