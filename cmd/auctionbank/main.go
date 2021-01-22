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
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/auction"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var dbFile = flag.String("dbfile", "bank.sqlite3", "Database file name")
var keyFile = flag.String("keyfile", "bank.keyfile", "Key file name")
var createFlag = flag.Bool("create", false, "Create initial database")

// dynamically select port with preference for 8123
var addr = flag.String("addr", "127.0.0.1:8123", "Address to listen on")
var db *sql.DB
var bankKey *crypto.SignatureSecrets

const preferredPort string = ":8123"

func dbInit() (err error) {
	_, err = db.Exec(`
		CREATE TABLE users (
			username VARCHAR(64) PRIMARY KEY,
			balance INTEGER
		)`)
	if err != nil {
		return
	}

	_, err = db.Exec(`
		CREATE TABLE auctions (
			auctionkey BLOB PRIMARY KEY,
			nextdepositid INTEGER,
			nextsettledid INTEGER
		)`)
	if err != nil {
		return
	}

	_, err = db.Exec(`
		CREATE TABLE auction_deposits (
			username VARCHAR(64),
			auctionkey BLOB,
			auctionid INTEGER,
			bidderkey BLOB,
			depositid INTEGER,
			amount INTEGER
		)`)
	if err != nil {
		return
	}

	return
}

// HTTP method handlers

type createUserQuery struct {
	Username string `schema:"username"`
}

func createUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	txHandleSuccess(w, func(tx *sql.Tx) error {
		var query createUserQuery
		err := readForm(&query, r)
		if err != nil {
			return err
		}

		if query.Username == "" {
			return fmt.Errorf("Missing username")
		}

		_, err = tx.Exec("INSERT INTO users (username, balance) VALUES (?, 0)", query.Username)
		return err
	})
}

type transferInQuery struct {
	Username string `schema:"username"`
	Amount   uint64 `schema:"amount"`
}

func transferIn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	txHandleSuccess(w, func(tx *sql.Tx) error {
		var query transferInQuery
		err := readForm(&query, r)
		if err != nil {
			return err
		}

		res, err := tx.Exec("UPDATE users SET balance=balance+? WHERE username=?",
			query.Amount, query.Username)
		if err != nil {
			return err
		}

		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}

		if affected == 0 {
			return fmt.Errorf("No such username")
		}

		return nil
	})
}

type transferOutQuery struct {
	Username string `schema:"username"`
	Amount   uint64 `schema:"amount"`
}

func transferOut(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	txHandleSuccess(w, func(tx *sql.Tx) error {
		var query transferOutQuery
		err := readForm(&query, r)
		if err != nil {
			return err
		}

		row := tx.QueryRow("SELECT balance FROM users WHERE username=?", query.Username)
		var balance uint64
		err = row.Scan(&balance)
		if err != nil {
			return err
		}

		row = tx.QueryRow("SELECT SUM(amount) FROM auction_deposits WHERE username=?", query.Username)
		var deposits sql.NullInt64
		err = row.Scan(&deposits)
		if err != nil {
			return err
		}

		if !deposits.Valid {
			deposits.Int64 = 0
		}

		if query.Amount+uint64(deposits.Int64) > balance {
			return fmt.Errorf("Amount %d exceeds balance %d - deposits %d", query.Amount, balance, deposits.Int64)
		}

		_, err = tx.Exec("UPDATE users SET balance=balance-? WHERE username=?", query.Amount, query.Username)
		if err != nil {
			return err
		}

		// A real system should actually transfer the money back to the user's
		// bank account, e.g., via ACH or other transfer mechanism.
		return nil
	})
}

type statusQuery struct {
	Username string `schema:"username"`
}

type statusResult struct {
	Success bool   `json:"success"`
	Balance uint64 `json:"balance"`
	Pending uint64 `json:"pending"`
}

func accountStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	txHandle(w, func(tx *sql.Tx) (interface{}, error) {
		var query statusQuery
		err := readForm(&query, r)
		if err != nil {
			return nil, err
		}

		var result statusResult

		row := tx.QueryRow("SELECT balance FROM users WHERE username=?", query.Username)
		err = row.Scan(&result.Balance)
		if err != nil {
			return nil, err
		}

		row = tx.QueryRow("SELECT SUM(amount) FROM auction_deposits WHERE username=?", query.Username)
		var deposits sql.NullInt64
		err = row.Scan(&deposits)
		if err != nil {
			return nil, err
		}

		if deposits.Valid {
			result.Pending = uint64(deposits.Int64)
		} else {
			result.Pending = 0
		}

		result.Success = true
		return result, nil
	})
}

type createAuctionsQuery struct {
	AuctionKey basics.Address `schema:"auction"`
}

func createAuctions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	txHandleSuccess(w, func(tx *sql.Tx) error {
		var query createAuctionsQuery
		err := readForm(&query, r)
		if err != nil {
			return err
		}

		// A real system should check that only authorized users (e.g., Algorand)
		// can register an auction with the bank.

		// In principle, auctionmaster allows specifying any initial AuctionID
		// in the `initparams.json` file, except for 0.  Here we assume the
		// auction starts with AuctionID 1, though.

		_, err = tx.Exec("INSERT INTO auctions (auctionkey, nextdepositid, nextsettledid) VALUES (?, 1, 1)", query.AuctionKey[:])
		return err
	})
}

type depositAuctionQuery struct {
	Username   string         `schema:"username"`
	AuctionKey basics.Address `schema:"auction"`
	BidderKey  basics.Address `schema:"bidder"`
	AuctionID  uint64         `schema:"auctionid"`
	Amount     uint64         `schema:"amount"`
}

type depositStatus struct {
	Success           bool               `json:"success"`
	SignedDepositNote client.BytesBase64 `json:"sigdepb64"`
}

func depositAuction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	txHandle(w, func(tx *sql.Tx) (interface{}, error) {

		logging.Base().Debugf("depositAuction request %+v", r)

		var query depositAuctionQuery
		err := readForm(&query, r)
		if err != nil {
			logging.Base().Errorf("error %+v", err)
			return nil, err
		}

		logging.Base().Debugf("depositAuctionQuery %+v", query)

		row := tx.QueryRow("SELECT balance FROM users WHERE username=?", query.Username)
		var balance uint64
		err = row.Scan(&balance)
		if err != nil {
			logging.Base().Errorf("error %+v", err)
			return nil, err
		}

		row = tx.QueryRow("SELECT SUM(amount) FROM auction_deposits WHERE username=?", query.Username)
		var deposits sql.NullInt64
		err = row.Scan(&deposits)
		if err != nil {
			logging.Base().Errorf("error %+v", err)
			return nil, err
		}

		if !deposits.Valid {
			deposits.Int64 = 0
		}

		if query.Amount+uint64(deposits.Int64) > balance {
			logging.Base().Errorf("error query.Amount+uint64(deposits.Int64) > balance")
			return nil, fmt.Errorf("amount %d exceeds balance %d - deposits %d", query.Amount, balance, deposits.Int64)
		}

		row = tx.QueryRow("SELECT nextdepositid, nextsettledid FROM auctions WHERE auctionkey=?", query.AuctionKey[:])
		var nextDepositID uint64
		var nextSettledID uint64
		err = row.Scan(&nextDepositID, &nextSettledID)
		if err != nil {
			logging.Base().Errorf("error %+v", err)
			return nil, err
		}

		if query.AuctionID < nextSettledID {
			logging.Base().Errorf("error query.AuctionID < nextSettledID")
			return nil, fmt.Errorf("auction ID %d below next settlement ID %d", query.AuctionID, nextSettledID)
		}

		// Prevent users from depositing money into auctions that are too
		// far in the future, which means the user wouldn't be able to get
		// their money back for a long time.
		if query.AuctionID > nextSettledID+5 {
			err = fmt.Errorf("auction ID %d is too far in the future, next ID is %d", query.AuctionID, nextSettledID)
			logging.Base().Errorf("error %d > %d, %s", query.AuctionID, nextSettledID+5, err.Error())
			return nil, err
		}

		rows, err := tx.Query("SELECT username FROM auction_deposits WHERE auctionkey=? AND auctionid=? AND bidderkey=?",
			query.AuctionKey[:], query.AuctionID, query.BidderKey[:])
		if err != nil {
			logging.Base().Errorf("error %+v", err)
			return nil, err
		}

		defer rows.Close()
		for rows.Next() {
			var name string
			err = rows.Scan(&name)
			if err != nil {
				logging.Base().Errorf("error %+v", err)
				return nil, err
			}

			if name != query.Username {
				logging.Base().Errorf("error %s != %s", name, query.Username)
				return nil, fmt.Errorf("deposit key already used by a different user")
			}
		}

		err = rows.Err()
		if err != nil {
			logging.Base().Errorf("error extracting rows %+v", err)
			return nil, err
		}

		_, err = tx.Exec("INSERT INTO auction_deposits (username, auctionkey, auctionid, bidderkey, depositid, amount) VALUES (?, ?, ?, ?, ?, ?)",
			query.Username, query.AuctionKey[:], query.AuctionID, query.BidderKey[:], nextDepositID, query.Amount)
		if err != nil {
			logging.Base().Errorf("error saving auction deposit to database: %v", err)
			return nil, err
		}

		res, err := tx.Exec("UPDATE auctions SET nextdepositid=nextdepositid+1 WHERE auctionkey=?", query.AuctionKey[:])
		if err != nil {
			logging.Base().Errorf("error updating actions with next deposit id %+v", err)
			return nil, err
		}

		affected, err := res.RowsAffected()
		if err != nil {
			logging.Base().Errorf("error %+v", err)
			return nil, err
		}

		if affected == 0 {
			logging.Base().Errorf("error affected == 0, unable to update next deposit ID")
			return nil, fmt.Errorf("unable to update next deposit ID")
		}

		sigDep := auction.SignedDeposit{
			Deposit: auction.Deposit{
				BidderKey:  crypto.Digest(query.BidderKey),
				Currency:   query.Amount,
				AuctionKey: crypto.Digest(query.AuctionKey),
				AuctionID:  query.AuctionID,
				DepositID:  nextDepositID,
			},
		}

		logging.Base().Debugf("sigDep =  %+v", sigDep)

		sigDep.Sig = bankKey.Sign(sigDep.Deposit)

		var status depositStatus
		status.Success = true
		status.SignedDepositNote = protocol.Encode(&auction.NoteField{
			Type:          auction.NoteDeposit,
			SignedDeposit: sigDep,
		})

		logging.Base().Debugf("depositStatus =  %+v", status)

		return status, nil
	})
}

type settleAuctionQuery struct {
	AuctionKey        basics.Address     `schema:"auction"`
	SigSettlementBlob client.BytesBase64 `schema:"sigsettle"`
	OutcomesBlob      client.BytesBase64 `schema:"outcomes"`
}

func settleAuction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	txHandleSuccess(w, func(tx *sql.Tx) error {
		var query settleAuctionQuery
		err := readForm(&query, r)
		if err != nil {
			return err
		}

		var sigSettlement auction.SignedSettlement
		err = protocol.Decode(query.SigSettlementBlob, &sigSettlement)
		if err != nil {
			return err
		}

		var outcomes auction.BidOutcomes
		err = protocol.Decode(query.OutcomesBlob, &outcomes)
		if err != nil {
			return err
		}

		if !sigSettlement.Settlement.VerifyBidOutcomes(outcomes) {
			return fmt.Errorf("BidOutcomes does not verify against Settlement")
		}

		row := tx.QueryRow("SELECT nextsettledid FROM auctions WHERE auctionkey=?", query.AuctionKey[:])
		var nextSettledID uint64
		err = row.Scan(&nextSettledID)
		if err != nil {
			return err
		}

		if !auction.VerifySignedSettlement(sigSettlement, crypto.Digest(query.AuctionKey), nextSettledID) {
			return fmt.Errorf("SignedSettlement does not verify for auction ID %d", nextSettledID)
		}

		_, err = tx.Exec("UPDATE auctions SET nextsettledid=nextsettledid+1 WHERE auctionkey=?", query.AuctionKey[:])
		if err != nil {
			return err
		}

		winners := make(map[crypto.Digest]uint64)
		for _, out := range outcomes.Outcomes {
			winners[out.BidderKey] += out.AlgosWon
		}

		for bidder, algos := range winners {
			currencyWon := algos * outcomes.Price

			row := tx.QueryRow("SELECT SUM(amount) FROM auction_deposits WHERE auctionkey=? AND auctionid=? AND bidderkey=?", query.AuctionKey[:], outcomes.AuctionID, bidder[:])
			var balance sql.NullInt64
			err = row.Scan(&balance)
			if err != nil {
				return err
			}

			if !balance.Valid {
				balance.Int64 = 0
			}

			if currencyWon > uint64(balance.Int64) {
				return fmt.Errorf("internal error: currency won %d exceeds deposit balance %d", currencyWon, balance.Int64)
			}

			row = tx.QueryRow("SELECT DISTINCT username FROM auction_deposits WHERE auctionkey=? AND auctionid=? AND bidderkey=?", query.AuctionKey[:], outcomes.AuctionID, bidder[:])
			var username string
			err = row.Scan(&username)
			if err != nil {
				return err
			}

			_, err = tx.Exec("UPDATE users SET balance=balance-? WHERE username=?", currencyWon, username)
			if err != nil {
				return err
			}
		}

		// Free up all deposits for this auction ID
		_, err = tx.Exec("DELETE FROM auction_deposits WHERE auctionkey=? AND auctionid=?", query.AuctionKey[:], outcomes.AuctionID)
		if err != nil {
			return err
		}

		return nil
	})
}

func main() {

	logging.Base().SetLevel(logging.Debug)
	flag.Parse()

	if *createFlag {
		_, err := os.Stat(*dbFile)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Database %s already exists\n", *dbFile)
			os.Exit(1)
		}

		_, err = os.Stat(*keyFile)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Key file %s already exists\n", *keyFile)
			os.Exit(1)
		}

		var seed crypto.Seed
		crypto.RandBytes(seed[:])
		err = ioutil.WriteFile(*keyFile, seed[:], 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot write key file %s: %v\n", *keyFile, err)
			os.Exit(1)
		}

		db, err = sql.Open("sqlite3", *dbFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Opening database %v: %v\n", *dbFile, err)
			os.Exit(1)
		}

		err = dbInit()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Initializing database: %v\n", err)
			os.Exit(1)
		}

		bankKey = crypto.GenerateSignatureSecrets(seed)
		fmt.Fprintf(os.Stderr, "Bank key: %s\n",
			basics.Address(bankKey.SignatureVerifier))

		os.Exit(0)
	}

	_, err := os.Stat(*dbFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Database %s does not exist\n", *dbFile)
		os.Exit(1)
	}

	db, err = sql.Open("sqlite3", *dbFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Opening database %v: %v\n", *dbFile, err)
		os.Exit(1)
	}

	var seed crypto.Seed
	seedBytes, err := ioutil.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read key file %s: %v\n", *keyFile, err)
		os.Exit(1)
	}

	if len(seedBytes) != len(seed) {
		fmt.Fprintf(os.Stderr, "Malformed key file %s\n", *keyFile)
		os.Exit(1)
	}

	copy(seed[:], seedBytes)
	bankKey = crypto.GenerateSignatureSecrets(seed)
	fmt.Fprintf(os.Stderr, "Bank key: %s\n",
		basics.Address(bankKey.SignatureVerifier))

	http.HandleFunc("/create-user", createUser)
	http.HandleFunc("/transfer-in", transferIn)
	http.HandleFunc("/transfer-out", transferOut)
	http.HandleFunc("/account-status", accountStatus)
	http.HandleFunc("/create-auctions", createAuctions)
	http.HandleFunc("/deposit-auction", depositAuction)
	http.HandleFunc("/settle-auction", settleAuction)

	err = listenAndServe(*addr, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "http.ListenAndServe: %v\n", err)
		os.Exit(1)
	}
}

// start listening on for REST request
func listenAndServe(addr string, handler http.Handler) (err error) {

	logging.Base().Infof("Preparing http server with address: %s", addr)

	if addr == "" {
		addr = ":http"
	}

	listener, err := makeListener(addr)

	if err != nil {
		logging.Base().Errorf("Could not start auction bank: %v", err)
		os.Exit(1)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	actualAddress := listener.Addr().(*net.TCPAddr).String()
	ipV4Host := "127.0.0.1"
	ipV4Address := fmt.Sprintf("%s:%d", ipV4Host, port)

	pid := os.Getpid()

	logging.Base().Infof("Binding to address: %s with port %d", actualAddress, port)

	pidFile := filepath.Join(".", "auctionbank.pid")
	netFile := filepath.Join(".", "auctionbank.net")

	logging.Base().Infof("Writing pid %d to file: %s", pid, pidFile)
	logging.Base().Infof("Writing address %s to file: %s", ipV4Address, netFile)

	ioutil.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", pid)), 0644)
	ioutil.WriteFile(netFile, []byte(fmt.Sprintf("%s\n", ipV4Address)), 0644)

	panic(http.Serve(listener, handler))
}

// helper handles startup of tcp listener
func makeListener(addr string) (net.Listener, error) {
	var listener net.Listener
	var err error
	if (addr == "127.0.0.1:0") || (addr == ":0") {
		// if port 0 is provided, prefer port 8123 first, then fall back to port 0
		preferredAddr := strings.Replace(addr, ":0", preferredPort, -1)
		listener, err = net.Listen("tcp", preferredAddr)
		if err == nil {
			return listener, err
		}
	}
	// err was not nil or :0 was not provided, fall back to originally passed addr
	return net.Listen("tcp", addr)
}
