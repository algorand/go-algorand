// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// RejectingLimitListener is a modification of LimitListener in
// "golang.org/x/net/netutil". The difference is that when the number of connections
// exceeds the limit, RejectingLimitListener will accept and immediately close all
// new connections.

package limitlistener

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/algorand/go-algorand/logging"
)

// RejectingLimitListener returns a Listener that accepts at most n simultaneous
// connections from the provided Listener. `log` can be nil.
func RejectingLimitListener(l net.Listener, n uint64, log logging.Logger) net.Listener {
	return &rejectingLimitListener{
		Listener: l,
		log:      log,
		sem:      make(chan struct{}, n),
		done:     make(chan struct{}),
	}
}

type rejectingLimitListener struct {
	net.Listener
	log       logging.Logger
	sem       chan struct{}
	closeOnce sync.Once     // ensures the done chan is only closed once
	done      chan struct{} // no values sent; closed when Close is called
}

func (l *rejectingLimitListener) release() {
	<-l.sem
}

func (l *rejectingLimitListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.done:
			return nil, errors.New("Accept() limit listener is closed")
		default:
			c, err := l.Listener.Accept()
			if err != nil {
				return nil, fmt.Errorf("Accept() accept err: %w", err)
			}
			select {
			case l.sem <- struct{}{}:
				return &rejectingLimitListenerConn{Conn: c, release: l.release}, nil
			default:
				// Close connection immediately.
				err = c.Close()
				if (err != nil) && (l.log != nil) {
					l.log.Debugf(
						"rejectingLimitListener.Accept() failed to close connection, err %v", err)
				}
			}
		}
	}
}

func (l *rejectingLimitListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.done) })
	return err
}

type rejectingLimitListenerConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (l *rejectingLimitListenerConn) Close() error {
	err := l.Conn.Close()
	l.releaseOnce.Do(l.release)
	return err
}

func (l *rejectingLimitListenerConn) UnderlyingConn() net.Conn {
	return l.Conn
}
