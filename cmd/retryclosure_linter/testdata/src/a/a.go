// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package a

import (
	"context"
	"database/sql"
	"strings"

	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/util/db"
	"wrap"
)

var global int

type thing struct {
	n    int
	sb   strings.Builder
	vals map[int]int
}

func scan(dst *int) error { *dst = 1; return nil }

func accumulates(acc *db.Accessor) ([]int, error) {
	var res []int
	err := acc.Atomic(func(ctx context.Context, tx *sql.Tx) error { // want `writes to res \(line 42, assign\)`
		res = append(res, 1)
		return nil
	})
	return res, err
}

func namedResult() (n int, err error) {
	err = db.Retry(func() error { // want `writes to n \(line 50, assign\), err \(line 50, assign\)`
		n, err = 1, nil
		return err
	})
	return
}

func localsOnly(acc *db.Accessor) error {
	return acc.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var local []int
		local = append(local, 1)
		inner := 0
		f := func() { inner++ }
		f()
		return nil
	})
}

func storedInVariable() error {
	count := 0
	fn := func() error {
		count++
		return nil
	}
	return db.Retry(fn) // want `writes to count \(line 70, incdec\)`
}

func withRetry(fn func() error) error { // want withRetry:`retriesParams\[0\]`
	return db.Retry(fn)
}

func throughLocalWrapper() (int, error) {
	x := 0
	return x, withRetry(func() error { // want `passed to a.withRetry .* writes to x \(line 83, assign\)`
		x = 1
		return nil
	})
}

func throughOtherPackageWrapper() (int, error) {
	x := 0
	return x, wrap.WithRetry(func() error { // want `passed to wrap.WithRetry .* writes to x \(line 91, assign\)`
		x = 1
		return nil
	})
}

func (t *thing) load() error {
	t.n = 1
	return nil
}

func methodValue(t *thing) error {
	return db.Retry(t.load) // want `writes to t \(line 97, assign\)`
}

func addressTaken() error {
	var v int
	return db.Retry(func() error { // want `writes to v \(line 108, addr\)`
		return scan(&v)
	})
}

func alias(t *thing) error {
	return db.Retry(func() error { // want `writes to m \(line 115, assign\)`
		m := t.vals
		m[1] = 2
		return nil
	})
}

func store(s trackerdb.Store) (int, error) {
	var got int
	return got, s.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error { // want `passed to Transaction .* writes to got \(line 123, assign\)`
		got = 1
		return nil
	})
}

func pointerMethodOnValue(t *thing) error {
	return db.Retry(func() error { // want `writes to t \(line 130, ptrmethod\)`
		t.sb.WriteString("x")
		return nil
	})
}

func packageVar() error {
	return db.Retry(func() error { // want `writes to global \(line 137, incdec\)`
		global++
		return nil
	})
}

func retryClearFnNotChecked(acc *db.Accessor, t *thing) error {
	return acc.AtomicContext(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		return nil
	}, func(context.Context) { t.n = 0 })
}

func uncheckable(fns []func() error) error {
	return db.Retry(fns[0]) // want `cannot check the function passed to db.Retry`
}
