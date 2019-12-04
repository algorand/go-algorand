package auction

//msgp:ignore SortUint64
//msgp:sort uint64 SortUint64
type SortUint64 []uint64

func (a SortUint64) Len() int           { return len(a) }
func (a SortUint64) Less(i, j int) bool { return a[i] < a[j] }
func (a SortUint64) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

//msgp:sort crypto.Digest crypto.SortDigest
