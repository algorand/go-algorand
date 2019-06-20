package leaktest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"
)

func index() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func startKeepAliveEnabledServer(ctx context.Context) *httptest.Server {
	server := httptest.NewUnstartedServer(index())
	server.Config.ReadTimeout = 5 * time.Second
	server.Config.WriteTimeout = 10 * time.Second
	server.Config.IdleTimeout = 15 * time.Second
	server.Config.SetKeepAlivesEnabled(true)

	server.Start()
	go func() {
		<-ctx.Done()
		server.Close()
	}()

	return server
}
