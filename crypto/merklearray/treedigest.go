package merklearray

// TreeDigest represents the digests the merklearray.Tree returns.
type TreeDigest interface {
	To32Byte() [32]byte
	ToSlice() []byte
}
