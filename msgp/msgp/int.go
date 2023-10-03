package msgp

// MaxInt is the maximum int, which might be int32 or int64
const MaxInt = int((^uint(0)) >> 1)

func u32int(x uint32) (int, error) {
	if uint64(x) > uint64(MaxInt) {
		return 0, ErrOverflow(uint64(x), uint64(MaxInt))
	}

	return int(x), nil
}

func u64int(x uint64) (int, error) {
	if x > uint64(MaxInt) {
		return 0, ErrOverflow(x, uint64(MaxInt))
	}

	return int(x), nil
}
