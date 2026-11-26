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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand. If not, see <https://www.gnu.org/licenses/>.

package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsEmptyWalkErrors(t *testing.T) {
	dir := t.TempDir()
	if IsEmpty(filepath.Join(dir, "missing")) {
		t.Fatal("missing path reported empty")
	}
	if !IsEmpty(dir) {
		t.Fatal("empty directory reported nonempty")
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if IsEmpty(filepath.Join(file, "child")) {
		t.Fatal("invalid path reported empty")
	}
	if IsEmpty(dir) {
		t.Fatal("directory containing a file reported empty")
	}
}
