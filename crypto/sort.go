package crypto

// SortDigest implements sorting by Digest keys for
// canonical encoding of maps in msgpack format.
//msgp:ignore SortDigest
type SortDigest []Digest

func (a SortDigest) Len() int      { return len(a) }
func (a SortDigest) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

func (a SortDigest) Less(i, j int) bool {
	for pos := 0; pos < len(a[i]); pos++ {
		if a[i][pos] < a[j][pos] {
			return true
		}
		if a[i][pos] > a[j][pos] {
			return false
		}
	}
	return false
}
