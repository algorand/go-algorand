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

package session

import (
	"context"
	"time"

	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/daemon/kmd/wallet"
	"github.com/algorand/go-deadlock"
)

type walletHandle struct {
	secret  []byte
	expires time.Time
	wallet  wallet.Wallet
}

// Manager allows users to initialize wallets by knowing their passwords, and
// stores the initialized wallets in memory where the user can access them by
// an ephemeral wallet handle token
type Manager struct {
	Initialized     bool
	walletHandles   map[string]walletHandle
	sessionLifetime time.Duration
	Kill            context.CancelFunc
	ctx             context.Context
	mux             deadlock.Mutex
}

// MakeManager initializes and returns a *Manager using the kmd global
// configuration
func MakeManager(cfg config.KMDConfig) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	sm := &Manager{
		Initialized:     true,
		walletHandles:   make(map[string]walletHandle),
		sessionLifetime: time.Duration(cfg.SessionLifetimeSecs * uint64(time.Second)),
		Kill:            cancel,
		ctx:             ctx,
	}
	go sm.cleanUpExpiredHandles()
	return sm
}
