// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package metrics

import (
	"fmt"
	"sync"
	"testing"
)

func TestTagCounter(t *testing.T) {
	tags := make([]string, 17)
	for i := range tags {
		tags[i] = fmt.Sprintf("A%c", 'A'+i)
	}
	//t.Logf("tags %v", tags)
	countsIn := make([]uint64, len(tags))
	for i := range countsIn {
		countsIn[i] = uint64(10 * (i + 1))
	}

	tc := NewTagCounter("tc", "wat")
	var wg sync.WaitGroup
	wg.Add(len(tags))

	runf := func(tag string, count uint64) {
		for i := 0; i < int(count); i++ {
			tc.Add(tag, 1)
		}
		wg.Done()
	}

	for i, tag := range tags {
		go runf(tag, countsIn[i])
	}
	wg.Wait()

	endtags := tc.tagptr.Load().(map[string]*uint64)
	for i, tag := range tags {
		countin := countsIn[i]
		endcountp := endtags[tag]
		if endcountp == nil {
			t.Errorf("tag[%d] %s nil counter", i, tag)
			continue
		}
		endcount := *endcountp
		if endcount != countin {
			t.Errorf("tag[%d] %v wanted %d got %d", i, tag, countin, endcount)
		}
	}
}

func BenchmarkTagCounter(b *testing.B) {
	b.Logf("b.N = %d", b.N)
	t := b
	tags := make([]string, 17)
	for i := range tags {
		tags[i] = fmt.Sprintf("A%c", 'A'+i)
	}
	//t.Logf("tags %v", tags)
	triangle := make([]int, len(tags))
	tsum := 0
	for i := range triangle {
		triangle[i] = i + 1
		tsum += i + 1
	}
	wholeN := b.N / tsum
	remainder := b.N - (tsum * wholeN)
	rchunk := (remainder / len(tags)) + 1
	countsIn := make([]uint64, len(tags))
	csum := uint64(0)
	for i := range countsIn {
		rcc := rchunk
		if remainder < rcc {
			rcc = remainder
			remainder = 0
		} else {
			remainder -= rchunk
		}
		countsIn[i] = uint64((triangle[i] * wholeN) + rcc)
		csum += countsIn[i]
	}
	if csum != uint64(b.N) {
		b.Errorf("b.N = %d, but total = %d", b.N, csum)
	}

	tc := NewTagCounter("tc", "wat")
	//var wg sync.WaitGroup
	//wg.Add(len(tags))

	runf := func(tag string, count uint64) {
		for i := 0; i < int(count); i++ {
			tc.Add(tag, 1)
		}
		//wg.Done()
	}

	for i, tag := range tags {
		// don't run in threads so that we can benchmark time
		runf(tag, countsIn[i])
	}
	//wg.Wait()

	endtags := tc.tagptr.Load().(map[string]*uint64)
	for i, tag := range tags {
		countin := countsIn[i]
		endcount := uint64(0)
		endcountp := endtags[tag]
		if endcountp != nil {
			endcount = *endcountp
			//t.Errorf("tag[%d] %s nil counter", i, tag)
			//continue
		}
		//endcount := *endcountp
		if endcount != countin {
			t.Errorf("tag[%d] %v wanted %d got %d", i, tag, countin, endcount)
		}
	}
}
