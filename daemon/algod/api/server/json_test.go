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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func jsonSerialize(tb testing.TB, s echo.JSONSerializer, v any, indent string) ([]byte, error) {
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
	err := s.Serialize(c, v, indent)
	return rec.Body.Bytes(), err
}

func requireSameJSON(t *testing.T, name string, v any) {
	for _, indent := range []string{"", "  "} {
		want, err := jsonSerialize(t, echo.DefaultJSONSerializer{}, v, indent)
		require.NoError(t, err, name)
		got, err := jsonSerialize(t, jsonSerializer{}, v, indent)
		require.NoError(t, err, name)
		require.Equal(t, string(want), string(got), "%s, indent %q", name, indent)
	}
}

// TestJSONSerializer checks that jsonSerializer writes what echo's default
// serializer writes, for the cases where encoding/json/v2's own defaults
// differ and for a response larger than the write buffer.
func TestJSONSerializer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	program := make([]byte, 1024)
	large := make([]model.AccountApplicationResource, 200)
	for i := range large {
		large[i] = model.AccountApplicationResource{Id: 1, Params: &model.ApplicationParams{ApprovalProgram: program}}
	}
	cases := map[string]any{
		"empty page":           model.AccountApplicationsInformationResponse{ApplicationResources: &[]model.AccountApplicationResource{}},
		"large page":           model.AccountApplicationsInformationResponse{ApplicationResources: &large},
		"nil slice":            model.Box{Value: []byte{}},
		"config with duration": config.GetDefaultLocal(),
		"unsorted map":         map[string]any{"b": 1, "a": 2, "B": 3},
		"escaping":             echo.Map{"message": "<b>&</b>\u2028 invalid \xff"},
		"bool":                 true,
	}
	for name, v := range cases {
		requireSameJSON(t, name, v)
	}
}
