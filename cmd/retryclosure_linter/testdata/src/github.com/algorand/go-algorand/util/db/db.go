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

// Package db is a stub of go-algorand's util/db, declaring the retrying functions.
package db

import (
	"context"
	"database/sql"
)

type Accessor struct{}

func (db *Accessor) Atomic(fn func(ctx context.Context, tx *sql.Tx) error, extras ...any) error {
	return fn(context.Background(), nil)
}

func (db *Accessor) AtomicContext(ctx context.Context, fn func(ctx context.Context, tx *sql.Tx) error, retryClearFn func(context.Context), extras ...any) error {
	return fn(ctx, nil)
}

func Retry(fn func() error) error { return fn() }
