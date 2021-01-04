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

package transactions

import (
	"errors"
	"math/rand"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// BalanceMap is a simple implementation of the balances interface.
type BalanceMap map[basics.Address]basics.BalanceRecord

func (b BalanceMap) Move(src, dst basics.Address, amount basics.MicroAlgos) error {
	var overflowed bool
	var tmp basics.MicroAlgos
	srcBal, ok := b[src]
	if !ok {
		return errors.New("Move() called with src not in tx.RelevantAddrs")
	}
	tmp, overflowed = basics.OSubA(srcBal.MicroAlgos, amount)
	if overflowed {
		return errors.New("Move(): sender overspent")
	}
	srcBal.MicroAlgos = tmp
	b[src] = srcBal

	dstBal, ok := b[dst]
	if !ok {
		return errors.New("Move() called with dst not in tx.RelevantAddrs")
	}
	tmp, overflowed = basics.OAddA(dstBal.MicroAlgos, amount)
	if overflowed {
		return errors.New("Move(): recipient balance overflowed")
	}
	dstBal.MicroAlgos = tmp
	b[dst] = dstBal

	return nil
}

func (b BalanceMap) Get(addr basics.Address) (basics.BalanceRecord, error) {
	record, ok := b[addr]
	if !ok {
		return basics.BalanceRecord{}, errors.New("Get() called on an address not in tx.RelevantAddrs")
	}
	return record, nil
}

func (b BalanceMap) Put(record basics.BalanceRecord) error {
	if _, ok := b[record.Addr]; !ok {
		return errors.New("Put() called on an account whose address was not in tx.RelevantAddrs")
	}
	b[record.Addr] = record
	return nil
}

// set up a BalanceMap for a transaction containing only the transactions RelevantAddrs.
func makeTestBalancesForTransaction(tx Transaction) BalanceMap {
	bals := make(BalanceMap)
	for _, addr := range tx.RelevantAddrs(SpecialAddresses{RewardsPool: poolAddr}) {
		bals[addr] = basics.BalanceRecord{Addr: addr}
	}
	return bals
}

func generateTestObjects(numTxs, numAccs int) ([]Transaction, []SignedTxn, []*crypto.SignatureSecrets, []basics.Address) {
	txs := make([]Transaction, numTxs)
	signed := make([]SignedTxn, numTxs)
	secrets := make([]*crypto.SignatureSecrets, numAccs)
	addresses := make([]basics.Address, numAccs)

	for i := 0; i < numAccs; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	for i := 0; i < numTxs; i++ {
		s := rand.Intn(numAccs)
		r := rand.Intn(numAccs)
		a := rand.Intn(1000)
		f := config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee + uint64(rand.Intn(10))
		iss := 50 + rand.Intn(30)
		exp := iss + 10

		txs[i] = Transaction{
			Type: protocol.PaymentTx,
			Header: Header{
				Sender:     addresses[s],
				Fee:        basics.MicroAlgos{Raw: f},
				FirstValid: basics.Round(iss),
				LastValid:  basics.Round(exp),
			},
			PaymentTxnFields: PaymentTxnFields{
				Receiver: addresses[r],
				Amount:   basics.MicroAlgos{Raw: uint64(a)},
			},
		}
		signed[i] = txs[i].Sign(secrets[s])
	}

	return txs, signed, secrets, addresses
}
