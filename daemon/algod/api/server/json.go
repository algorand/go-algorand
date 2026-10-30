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

package server

import (
	"bufio"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"sync"

	"github.com/labstack/echo/v4"
)

// jsonWriters buffers each response so the connection sees 64 KiB writes
// rather than the 4 KiB pieces the encoder flushes.
var jsonWriters = sync.Pool{New: func() any { return bufio.NewWriterSize(nil, 64<<10) }}

// jsonSerializer streams each response to the client. echo's default
// serializer builds the whole response in memory first, and a paginated
// response can be megabytes. DefaultOptionsV1 keeps the output identical to
// encoding/json's.
type jsonSerializer struct{}

func (jsonSerializer) Serialize(c echo.Context, i any, indent string) error {
	opts := jsonv1.DefaultOptionsV1()
	if indent != "" {
		opts = json.JoinOptions(opts, jsontext.WithIndent(indent))
	}
	w := jsonWriters.Get().(*bufio.Writer)
	w.Reset(c.Response())
	defer func() {
		w.Reset(nil)
		jsonWriters.Put(w)
	}()
	if err := json.MarshalWrite(w, i, opts); err != nil {
		return err
	}
	// encoding/json's Encoder ends each value with a newline.
	if err := w.WriteByte('\n'); err != nil {
		return err
	}
	return w.Flush()
}

func (jsonSerializer) Deserialize(c echo.Context, i any) error {
	return echo.DefaultJSONSerializer{}.Deserialize(c, i)
}
