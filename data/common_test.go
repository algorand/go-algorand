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

package data

import (
	"fmt"
	"math/rand"
	"strconv"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

var sinkAddr = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var genesisHash = crypto.Digest{0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}
var genesisID = "testingid"

var proto = config.Consensus[protocol.ConsensusCurrentVersion]

const mockBalancesMinBalance = 1000
const defaultRewardUnit = 1e6

func keypair() *crypto.SignatureSecrets {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

func testingenv(t testing.TB, numAccounts, numTxs int, offlineAccounts bool) (*Ledger, []account.Root, []account.Participation, []transactions.SignedTxn, func()) {
	P := numAccounts               // n accounts
	TXs := numTxs                  // n txns
	maxMoneyAtStart := 1000000     // max money start
	minMoneyAtStart := 100000      // max money start
	transferredMoney := 100        // max money/txn
	maxFee := 10                   // max maxFee/txn
	lastValid := basics.Round(500) // max round

	accessors := []db.Accessor{}

	release := func() {
		for _, acc := range accessors {
			acc.Close()
		}

	}

	// generate accounts
	genesis := make(map[basics.Address]basics.AccountData)
	gen := rand.New(rand.NewSource(2))
	roots := make([]account.Root, P)
	parts := make([]account.Participation, P)
	for i := 0; i < P; i++ {
		access, err := db.MakeAccessor(t.Name()+"_root_testingenv"+strconv.Itoa(i), false, true)
		if err != nil {
			panic(err)
		}
		accessors = append(accessors, access)

		root, err := account.GenerateRoot(access)
		if err != nil {
			panic(err)
		}

		access, err = db.MakeAccessor(t.Name()+"_part_testingenv"+strconv.Itoa(i), false, true)
		if err != nil {
			panic(err)
		}
		accessors = append(accessors, access)

		part, err := account.FillDBWithParticipationKeys(access, root.Address(), 0, lastValid, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
		if err != nil {
			panic(err)
		}

		roots[i] = root
		parts[i] = part

		startamt := basics.MicroAlgos{Raw: uint64(minMoneyAtStart + (gen.Int() % (maxMoneyAtStart - minMoneyAtStart)))}
		short := root.Address()

		if offlineAccounts && i > P/2 {
			genesis[short] = basics.MakeAccountData(basics.Offline, startamt)
		} else {
			data := basics.MakeAccountData(basics.Online, startamt)
			data.SelectionID = parts[i].VRFSecrets().PK
			data.VoteID = parts[i].VotingSecrets().OneTimeSignatureVerifier
			genesis[short] = data
		}
	}

	genesis[poolAddr] = basics.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 100000 * proto.RewardsRateRefreshInterval})

	bootstrap := MakeGenesisBalances(genesis, poolAddr, sinkAddr)

	// generate test transactions
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := LoadLedger(logging.Base(), t.Name(), inMem, protocol.ConsensusCurrentVersion, bootstrap, genesisID, genesisHash, nil, cfg)
	if err != nil {
		panic(err)
	}

	tx := make([]transactions.SignedTxn, TXs)
	latest := ledger.Latest()
	if latest != 0 {
		panic(fmt.Errorf("newly created ledger doesn't start on round 0"))
	}
	bal := bootstrap.balances

	for i := 0; i < TXs; i++ {
		send := gen.Int() % P
		recv := gen.Int() % P

		saddr := roots[send].Address()
		raddr := roots[recv].Address()

		if proto.MinTxnFee+uint64(maxFee) > bal[saddr].MicroAlgos.Raw {
			continue
		}

		xferMax := transferredMoney
		if uint64(xferMax) > bal[saddr].MicroAlgos.Raw-proto.MinTxnFee-uint64(maxFee) {
			xferMax = int(bal[saddr].MicroAlgos.Raw - proto.MinTxnFee - uint64(maxFee))
		}

		if xferMax == 0 {
			continue
		}

		amt := basics.MicroAlgos{Raw: uint64(gen.Int() % xferMax)}
		fee := basics.MicroAlgos{Raw: uint64(gen.Int()%maxFee) + proto.MinTxnFee}

		t := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      saddr,
				Fee:         fee,
				FirstValid:  ledger.LastRound(),
				LastValid:   ledger.LastRound() + lastValid,
				Note:        make([]byte, 4),
				GenesisHash: genesisHash,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: raddr,
				Amount:   amt,
			},
		}

		rand.Read(t.Note)
		//if reallySignTxs {
		tx[i] = t.Sign(roots[send].Secrets())
		//} else {
		//	tx[i] = transactions.SignedTxn{Transaction: t, Sig: crypto.Signature{}}
		//}

		sbal := bal[saddr]
		sbal.MicroAlgos.Raw -= fee.Raw
		sbal.MicroAlgos.Raw -= amt.Raw
		bal[saddr] = sbal

		ibal := bal[poolAddr]
		ibal.MicroAlgos.Raw += fee.Raw
		bal[poolAddr] = ibal

		rbal := bal[raddr]
		rbal.MicroAlgos.Raw += amt.Raw
		bal[raddr] = rbal
	}

	return ledger, roots, parts, tx, release
}
