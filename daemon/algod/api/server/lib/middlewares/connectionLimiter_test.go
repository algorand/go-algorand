// Copyright (C) 2019-2024 Algorand, Inc.
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

package middlewares_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	"github.com/algorand/go-algorand/daemon/algod/api/server/lib/middlewares"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestConnectionLimiterBasic(t *testing.T) {
	partitiontest.PartitionTest(t)

	e := echo.New()

	handlerCh := make(chan struct{})
	limit := 5
	handler := func(c echo.Context) error {
		<-handlerCh
		return c.String(http.StatusOK, "test")
	}
	middleware := middlewares.MakeConnectionLimiter(uint64(limit))

	numConnections := 13
	for i := 0; i < 3; i++ {
		var recorders []*httptest.ResponseRecorder
		doneCh := make(chan int)
		errCh := make(chan error)

		for index := 0; index < numConnections; index++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			recorders = append(recorders, rec)

			go func(index int) {
				err := middleware(handler)(ctx)
				doneCh <- index
				errCh <- err
			}(index)
		}

		// Check http 429 code.
		for j := 0; j < numConnections-limit; j++ {
			index := <-doneCh
			assert.Equal(t, http.StatusTooManyRequests, recorders[index].Code)
		}

		// Let handlers finish.
		for j := 0; j < limit; j++ {
			handlerCh <- struct{}{}
		}

		// All other connections must return 200.
		for j := 0; j < limit; j++ {
			index := <-doneCh
			assert.Equal(t, http.StatusOK, recorders[index].Code)
		}

		// Check that no errors were returned by the middleware.
		for i := 0; i < numConnections; i++ {
			assert.NoError(t, <-errCh)
		}
	}
}

func TestConnectionLimiterForwardsError(t *testing.T) {
	partitiontest.PartitionTest(t)

	handlerError := errors.New("handler error")
	handler := func(c echo.Context) error {
		return handlerError
	}
	middleware := middlewares.MakeConnectionLimiter(1)

	err := middleware(handler)(nil)
	assert.ErrorIs(t, err, handlerError)
}
