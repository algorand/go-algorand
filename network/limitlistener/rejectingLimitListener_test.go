// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package limitlistener_test

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/algorand/go-algorand/network/limitlistener"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const defaultMaxOpenFiles = 256
const timeout = 5 * time.Second

func TestRejectingLimitListenerBasic(t *testing.T) {
	partitiontest.PartitionTest(t)

	const limit = 5
	// maximum length of accept queue is 128 by default
	attempts := min((maxOpenFiles()-limit)/2, 256)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l = limitlistener.RejectingLimitListener(l, limit, nil)

	server := http.Server{}
	handlerCh := make(chan struct{})
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-handlerCh
		fmt.Fprint(w, "some body")
	})
	go server.Serve(l)
	defer server.Close()

	for i := 0; i < 3; i++ {
		queryCh := make(chan error)
		for j := 0; j < attempts; j++ {
			go func() {
				c := http.Client{}
				r, err := c.Get("http://" + l.Addr().String())
				if err != nil {
					queryCh <- err
					return
				}

				io.Copy(io.Discard, r.Body)
				r.Body.Close()

				queryCh <- nil
			}()
		}

		for j := 0; j < attempts-limit; j++ {
			err := <-queryCh
			if err == nil {
				t.Errorf("this connection should have failed")
			}
		}

		for j := 0; j < limit; j++ {
			handlerCh <- struct{}{}
			err := <-queryCh
			if err != nil {
				t.Errorf("this connection should have been successful, err: %v", err)
			}
		}

		// Give the rejecting limit listener time to update its semaphor.
		time.Sleep(time.Millisecond)
	}
}

type errorListener struct {
	net.Listener
}

func (errorListener) Accept() (net.Conn, error) {
	return nil, errFake
}

var errFake = errors.New("fake error from errorListener")

func TestRejectingLimitListenerBaseListenerError(t *testing.T) {
	partitiontest.PartitionTest(t)

	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		const n = 2
		ll := limitlistener.RejectingLimitListener(errorListener{}, n, nil)
		for i := 0; i < n+1; i++ {
			_, err := ll.Accept()
			if !errors.Is(err, errFake) {
				errCh <- fmt.Errorf("Accept error %v doesn't contain errFake", err)
				return
			}
		}
	}()

	select {
	case err, ok := <-errCh:
		if ok {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(timeout):
		t.Fatal("timeout. deadlock?")
	}
}

func TestRejectingLimitListenerClose(t *testing.T) {
	partitiontest.PartitionTest(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ln = limitlistener.RejectingLimitListener(ln, 1, nil)

	err = ln.Close()
	if err != nil {
		t.Errorf("unsuccessful ln.Close()")
	}

	c, err := ln.Accept()
	if err == nil {
		c.Close()
		t.Errorf("unexpected successful Accept()")
	}
}
