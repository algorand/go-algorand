package basics

// SortAssetIndex implements sorting by AssetIndex keys for
// canonical encoding of maps in msgpack format.
//msgp:ignore SortAssetIndex
//msgp:sort AssetIndex SortAssetIndex
type SortAssetIndex []AssetIndex

func (a SortAssetIndex) Len() int           { return len(a) }
func (a SortAssetIndex) Less(i, j int) bool { return a[i] < a[j] }
func (a SortAssetIndex) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
