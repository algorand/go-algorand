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

package network

import (
	"encoding/base64"
	"fmt"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

type netPrioStub struct {
	addr  basics.Address
	prio  uint64
	peers map[basics.Address]uint64
	mu    deadlock.Mutex
}

type netPrioStubResponse struct {
	Nonce string
	Addr  basics.Address
	Prio  uint64
}

func (nps *netPrioStub) NewPrioChallenge() string {
	var rand [32]byte
	crypto.RandBytes(rand[:])
	return base64.StdEncoding.EncodeToString(rand[:])
}

func (nps *netPrioStub) MakePrioResponse(challenge string) []byte {
	r := netPrioStubResponse{
		Nonce: challenge,
		Addr:  nps.addr,
		Prio:  nps.prio,
	}
	return protocol.EncodeReflect(r)
}

func (nps *netPrioStub) VerifyPrioResponse(challenge string, response []byte) (addr basics.Address, err error) {
	var r netPrioStubResponse
	err = protocol.DecodeReflect(response, &r)
	if err != nil {
		return
	}

	if r.Nonce != challenge {
		err = fmt.Errorf("nonce mismatch")
		return
	}

	nps.mu.Lock()
	defer nps.mu.Unlock()

	if nps.peers == nil {
		nps.peers = make(map[basics.Address]uint64)
	}

	nps.peers[r.Addr] = r.Prio

	addr = r.Addr
	return
}

func (nps *netPrioStub) GetPrioWeight(addr basics.Address) uint64 {
	nps.mu.Lock()
	defer nps.mu.Unlock()

	if nps.peers == nil {
		return 0
	}

	return nps.peers[addr]
}
