// Copyright (C) 2019 Algorand, Inc.
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

package middlewares

import (
	"net/http"
	"time"

	"github.com/algorand/go-algorand/logging"
)

// LoggingResponseWriter will encapsulate a standard ResponseWriter with a copy of its statusCode
type LoggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// ResponseWriterWrapper is supposed to capture statusCode from ResponseWriter
func ResponseWriterWrapper(w http.ResponseWriter) *LoggingResponseWriter {
	return &LoggingResponseWriter{w, http.StatusOK}
}

// WriteHeader adds a header to each response
func (lrw *LoggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// Logger is a gorilla/mux middleware to add log to the API
func Logger(log logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapper := ResponseWriterWrapper(w)
			next.ServeHTTP(wrapper, r)
			log.Infof("%s %s %s [%v] \"%s %s %s\" %d %d \"%s\" %s",
				r.RemoteAddr,
				"-",
				"-",
				start,
				r.Method,
				r.RequestURI,
				r.Proto, // string "HTTP/1.1"
				wrapper.statusCode,
				r.ContentLength,
				r.Header["User-Agent"],
				time.Since(start),
			)
		})
	}
}
