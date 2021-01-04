// Copyright (C) 2019-2021 Algorand, Inc.
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

package main

import (
	"fmt"

	"net/http"
	"os"
	"strings"
	"time"

	"github.com/algorand/websocket"

	"github.com/algorand/go-algorand/cmd/tealdbg/cdt"
)

type wsClient struct {
	conn     *websocket.Conn
	received bool
}

func (c *wsClient) Connect(url string) error {
	var websocketDialer = websocket.Dialer{
		HandshakeTimeout:  45 * time.Second,
		EnableCompression: false,
	}

	requestHeader := make(http.Header)
	conn, _, err := websocketDialer.Dial(url, requestHeader)
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

func (c *wsClient) SendJSON(data interface{}) error {
	return c.conn.WriteJSON(data)
}

func (c *wsClient) Receive(buf []byte) (int, error) {
	if !c.received {
		c.conn.SetReadLimit(2 * 1024 * 1024)
		c.received = true
	}
	_, msg, err := c.conn.ReadMessage()
	if err != nil && !strings.HasSuffix(err.Error(), "close 1000 (normal)") {
		return 0, err
	}
	copy(buf, msg)
	return len(msg), nil
}

func (c *wsClient) Close() {
	c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(5*time.Second))
	c.conn.CloseWithoutFlush()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <ws url to connect>\n", os.Args[0])
		os.Exit(1)
	}
	url := os.Args[1]

	var client wsClient
	var err error
	data := make([]byte, 1024)

	if err = client.Connect(url); err != nil {
		fmt.Printf("Connect error: %v\n", err)
		os.Exit(1)
	}

	var counter int64 = 1
	req := cdt.ChromeRequest{ID: counter, Method: "Debugger.Enable"}
	counter++

	if err = client.SendJSON(req); err != nil {
		fmt.Printf("Send error: %v", err)
		os.Exit(1)
	}
	if _, err = client.Receive(data); err != nil {
		fmt.Printf("Recv error: %v", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", string(data))

	req = cdt.ChromeRequest{ID: counter, Method: "Runtime.runIfWaitingForDebugger"}
	counter++

	if err = client.SendJSON(req); err != nil {
		fmt.Printf("Send error: %v", err)
		os.Exit(1)
	}
	if _, err = client.Receive(data); err != nil {
		fmt.Printf("Recv error: %v", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", string(data))

	req = cdt.ChromeRequest{ID: counter, Method: "Debugger.resume"}
	counter++

	if err = client.SendJSON(req); err != nil {
		fmt.Printf("Send error: %v", err)
		os.Exit(1)
	}
	if _, err = client.Receive(data); err != nil {
		fmt.Printf("Recv error: %v", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", string(data))

	client.Close()
}
