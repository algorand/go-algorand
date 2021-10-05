package ledger

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/kvstore"
)

const (
	kvPrefixAccountRounds = "\x00\x00\x00\x01"

	kvPrefixAccount         = "\x00\x00\x00\x02"
	kvPrefixAccountEndRange = "\x00\x00\x00\x03"

	kvPrefixAccountBalance         = "\x00\x00\x00\x03"
	kvPrefixAccountBalanceEndRange = "\x00\x00\x00\x04"

	kvPrefixAssetCreators         = "\x00\x00\x00\x04"
	kvPrefixAssetCreatorsEndRange = "\x00\x00\x00\x05"

	kvPrefixAccountTotals = "\x00\x00\x00\x05"
	kvPrefixAccountHashes = "\x00\x00\x00\x06"
)

// return the big-endian binary encoding of a uint64
func bigEndianUint64(v uint64) []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, v)
	return ret
}

// accountKey: 4-byte prefix + 32-byte address
func accountKey(address []byte) []byte {
	return append([]byte(kvPrefixAccount), address...)
}

// accountBalanceKey: 4-byte prefix + 8-byte big-endian uint64 + 32-byte address
func accountBalanceKey(normBalance uint64, address []byte) []byte {
	ret := []byte(kvPrefixAccountBalance)
	ret = append(ret, bigEndianUint64(normBalance)...)
	ret = append(ret, address...)
	return ret
}

func splitAccountBalanceKey(key []byte) (normBalance uint64, address []byte, err error) {
	if len(key) != 44 {
		err = fmt.Errorf("splitAccountBalanceKey not correct length")
		return
	}
	normBalance = binary.BigEndian.Uint64(key[4:12])
	address = key[12:44]
	return
}

// accountRoundsKey: 4-byte prefix + string (e.g. "acctbase")
func accountRoundsKey(id string) []byte {
	return append([]byte(kvPrefixAccountRounds), []byte(id)...)
}

// assetCreatorsKey: 4-byte prefix + 8-byte big-endian (CreatableType uint64) + 8-byte big-endian uint64 (CreatableIndex)
func assetCreatorsKey(ctype basics.CreatableType, cidx basics.CreatableIndex) []byte {
	ret := []byte(kvPrefixAssetCreators)
	// XXX could save some bytes with a shorter ctype
	ret = append(ret, bigEndianUint64(uint64(ctype))...)
	ret = append(ret, bigEndianUint64(uint64(cidx))...)
	return ret
}

func splitAssetCreatorsKey(key []byte) (ctype basics.CreatableType, cidx basics.CreatableIndex, err error) {
	if len(key) != 20 {
		err = fmt.Errorf("splitAssetCreators key not correct length")
		return
	}
	ctype = basics.CreatableType(binary.BigEndian.Uint64(key[4:12]))
	cidx = basics.CreatableIndex(binary.BigEndian.Uint64(key[12:20]))
	return
}

// accountTotalsKey: 4-byte prefix + string (e.g. "" or "catchpointStaging")
func accountsTotalsKey(id string) []byte {
	return append([]byte(kvPrefixAccountTotals), []byte(id)...)
}

// accountHashesKey: 4-byte prefix + 8-byte big-endian uint64 (page ID)
func accountHashesKey(id uint64) []byte {
	ret := []byte(kvPrefixAccountHashes)
	ret = append(ret, bigEndianUint64(id)...)
	return ret
}

type accountKV struct {
	kvstore.KVStore
}

type kvRead interface {
	Get([]byte) ([]byte, error)
	NewIterator(start, end []byte, reverse bool) kvstore.Iterator
}

type kvSnapshottableRead interface {
	kvRead
	NewSnapshot() kvstore.Snapshot
}

type kvMultiGet interface {
	kvRead
	MultiGet([][]byte) ([][]byte, error)
}

type kvWrite interface {
	Set(key, value []byte) error
	Delete(key []byte) error
}

type atomicWriteTx struct {
	sqlTx   *sql.Tx
	kvWrite kvWrite
	kv      kvstore.KVStore
}

type atomicReadTx struct {
	sqlTx  *sql.Tx
	kvRead kvRead
}

// experimental helper to allow both sql.Tx and kvstore.BatchWriter to coexist
func atomicWrites(dbs db.Pair, kv kvstore.KVStore, f func(context.Context, *atomicWriteTx) error) error {
	return dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		batch := kv.NewBatch()
		atx := &atomicWriteTx{sqlTx: tx, kvWrite: batch, kv: kv} //, kvRead: au.kv}
		err := f(ctx, atx)
		// KV commit before learning if SQL commit succeeded (XXX switch?)
		if err == nil {
			batch.Commit()
		} else {
			batch.Cancel()
		}
		return err
	})
}

// writeBarrier commits and starts a new batch
func (t *atomicWriteTx) writeBarrier() {
	batch := (t.kvWrite).(kvstore.BatchWriter)
	batch.Commit()
	t.kvWrite = t.kv.NewBatch()
}

// experimental helper to allow both sql.Tx and kvstore.Snapshot to coexist
func atomicReads(dbs db.Pair, kv kvstore.KVStore, f func(context.Context, *atomicReadTx) error) error {
	return dbs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// using read snapshot to provide consistent reads
		snap := kv.NewSnapshot()
		defer snap.Close()
		atx := &atomicReadTx{sqlTx: tx, kvRead: snap}
		return f(ctx, atx)
	})
}

// XXX use the same row ID for all KV rows, just to have something non-zero
var kvRowID = sql.NullInt64{Int64: 1, Valid: true}

// kvResult implements sql.Result
type kvResult struct {
	lastID, rows int64
	err          error
}

func (r kvResult) LastInsertId() (int64, error) { return r.lastID, r.err }
func (r kvResult) RowsAffected() (int64, error) { return r.rows, r.err }

// simulate SELECT rowid, data FROM accountbase WHERE address=?
func kvGetAccountData(kv kvRead, address []byte, rowid *sql.NullInt64, acctData *[]byte) error {
	val, err := kv.Get(accountKey(address))
	if err != nil { // XXX assume any error is ErrNoRows
		return sql.ErrNoRows
	}
	*acctData = val
	*rowid = kvRowID
	return nil
}

// simulate SELECT accountbase.rowid, rnd, data FROM acctrounds LEFT JOIN accountbase ON address=? WHERE id='acctbase'
func kvGetAccountDataRound(kv kvMultiGet, address []byte, rowid *sql.NullInt64, rnd *basics.Round, acctData *[]byte) error {
	// atomic multiget of round number and account data
	vals, err := kv.MultiGet([][]byte{accountRoundsKey("acctbase"), accountKey(address)})
	if err != nil {
		return err
	}
	if len(vals) != 2 {
		return fmt.Errorf("kvGetAccountDataRound vals len %d", len(vals))
	}
	*rnd = basics.Round(binary.BigEndian.Uint64(vals[0]))
	*acctData = vals[1]
	*rowid = kvRowID
	return nil
}

// simulate INSERT INTO accountbase (address, normalizedonlinebalance, data) VALUES (?, ?, ?)
func kvInsertAccount(kv kvWrite, address []byte, normBalance uint64, data []byte) (sql.Result, error) {
	// write account data KV
	err := kv.Set(accountKey(address), data)
	if err != nil {
		return kvResult{err: err}, err
	}
	// write secondary index on balance
	err = kv.Set(accountBalanceKey(normBalance, address), []byte{})
	if err != nil {
		return kvResult{err: err}, err
	}
	return kvResult{lastID: 1, rows: 1}, nil
}

func kvDeleteAccount(kv kvWrite, address []byte, normBalance uint64) (sql.Result, error) {
	// delete account data KV
	err := kv.Delete(accountKey(address))
	if err != nil {
		return kvResult{err: err}, err
	}
	// delete secondary index on balance
	err = kv.Delete(accountBalanceKey(normBalance, address))
	if err != nil {
		return kvResult{err: err}, err
	}
	return kvResult{lastID: 1, rows: 1}, nil
}

func kvUpdateAccount(kv kvWrite, address []byte, newNormBalance, oldNormBalance uint64, data []byte) (sql.Result, error) {
	// (over)write account data KV
	err := kv.Set(accountKey(address), data)
	if err != nil {
		return kvResult{err: err}, err
	}
	// delete old secondary index on balance
	err = kv.Delete(accountBalanceKey(oldNormBalance, address))
	if err != nil {
		return kvResult{err: err}, err
	}
	// write new secondary index on balance
	err = kv.Set(accountBalanceKey(newNormBalance, address), []byte{})
	if err != nil {
		return kvResult{err: err}, err
	}
	return kvResult{lastID: 1, rows: 1}, nil
}

type accountIterator interface {
	Err() error
	Scan(...interface{}) error // will behave as (key *[]byte, val *[]byte)
	Next() bool
	Close() error
}

type kvAccountIterator struct {
	first bool
	it    kvstore.Iterator
}

func newKVAccountIterator(kv kvRead) *kvAccountIterator {
	return &kvAccountIterator{
		first: true,
		it:    kv.NewIterator([]byte(kvPrefixAccount), []byte(kvPrefixAccountEndRange), false),
	}
}
func (i *kvAccountIterator) Err() error { return nil }
func (i *kvAccountIterator) Close() error {
	i.it.Close()
	return nil
}

func (i *kvAccountIterator) Next() bool {
	if i.first {
		i.first = false
	} else {
		i.it.Next()
	}
	return i.it.Valid()
}

func (i *kvAccountIterator) Scan(args ...interface{}) error {
	// key *[]byte, val *[]byte
	if len(args) != 2 {
		return fmt.Errorf("kvAccountIterator Scan args should be 2, got %d", len(args))
	}
	key := (args[0]).(*[]byte)
	val := (args[1]).(*[]byte)
	ik := i.it.KeySlice()
	defer ik.Free()
	iv, err := i.it.ValueSlice()
	if err != nil {
		return err
	}
	defer iv.Free()
	prefixLen := len(kvPrefixAccount)
	k := make([]byte, ik.Size()-prefixLen)
	v := make([]byte, iv.Size())
	copy(k[:], ik.Data()[prefixLen:])
	copy(v[:], iv.Data())
	*key = k
	*val = v
	return nil
}

// simulate tx.Query("SELECT address, data FROM accountbase WHERE normalizedonlinebalance>0 ORDER BY normalizedonlinebalance DESC, address DESC LIMIT ? OFFSET ?", n, offset)
func kvTopAccounts(kv kvRead, offset, maxResults uint64) (accountIterator, error) {
	// reverse iterate over range starting from prefix for "balance 1" (0x0...01) to end of keyspace
	iter := kv.NewIterator(
		accountBalanceKey(1, []byte{}),
		[]byte(kvPrefixAccountBalanceEndRange),
		true)
	for i := uint64(0); i < offset && iter.Valid(); i++ { // simulate OFFSET
		iter.Next()
	}
	return &kvAccountBalanceIterator{kv: kv, first: true, it: iter, maxResults: maxResults}, nil
}

type kvAccountBalanceIterator struct {
	kv         kvRead
	first      bool
	it         kvstore.Iterator
	cnt        uint64
	maxResults uint64
}

func (i *kvAccountBalanceIterator) Err() error { return nil }
func (i *kvAccountBalanceIterator) Close() error {
	i.it.Close()
	return nil
}

func (i *kvAccountBalanceIterator) Next() bool {
	if i.first {
		i.first = false
	} else {
		i.it.Next()
	}
	// stop being valid after maxResults is met
	i.cnt++
	if i.cnt > i.maxResults {
		return false
	}
	return i.it.Valid()
}

func (i *kvAccountBalanceIterator) Scan(args ...interface{}) error {
	// key *[]byte, val *[]byte
	if len(args) != 2 {
		return fmt.Errorf("kvAccountIterator Scan args should be 2, got %d", len(args))
	}
	outAddr := (args[0]).(*[]byte)
	outData := (args[1]).(*[]byte)

	_, addr, err := splitAccountBalanceKey(i.it.Key())
	if err != nil {
		return err
	}
	data, err := i.kv.Get(accountKey(addr))
	if err != nil {
		return err
	}

	*outAddr = addr
	*outData = data
	return nil
}

type DBImpl interface {
	CountAccounts(r Reader) (uint64, error)
	GetAccountRound(r Reader, id string) (basics.Round, error)
}

func kvCountAccounts(kv kvRead) (uint64, error) {
	count := uint64(0)
	iter := kv.NewIterator([]byte(kvPrefixAccount), []byte(kvPrefixAccountEndRange), false)
	for ; iter.Valid(); iter.Next() {
		count++
	}
	iter.Close()
	if count == 0 {
		return 0, sql.ErrNoRows
	}
	return count, nil
}

func kvGetAccountRound(kv kvRead, id string) (basics.Round, error) {
	val, err := kv.Get(accountRoundsKey(id))
	if err != nil {
		return 0, err
	}
	if len(val) != 8 {
		return 0, fmt.Errorf("get acctrounds returned val of len %d", len(val))
	}
	return basics.Round(binary.BigEndian.Uint64(val)), nil
}

func kvPutAccountRounds(kv kvWrite, id string, rnd basics.Round) error {
	fmt.Println("kvPutAccountRounds id", id, "round", rnd)
	val := make([]byte, 8)
	binary.BigEndian.PutUint64(val, uint64(rnd))
	return kv.Set(accountRoundsKey(id), val)
}

func kvUpdateAccountRounds(kvR kvRead, kvW kvWrite, id string, rnd basics.Round) (sql.Result, error) {
	// get current value, to simulate "UPDATE acctrounds SET rnd=? WHERE id='acctbase' AND rnd<?", rnd, rnd)"
	oldRnd, err := kvGetAccountRound(kvR, id)
	if err != nil {
		return kvResult{err: err}, err
	}
	if !(oldRnd < rnd) { // don't update if "AND rnd<?" is not met
		return kvResult{rows: 0}, nil
	}

	val := make([]byte, 8)
	binary.BigEndian.PutUint64(val, uint64(rnd))
	err = kvW.Set(accountRoundsKey(id), val)
	if err != nil {
		return kvResult{err: err}, err
	}
	return kvResult{rows: 1}, nil
}

func kvGetAccountsTotals(kv kvRead, idKey string) (totals ledgercore.AccountTotals, err error) {
	var encTotals []byte
	encTotals, err = kv.Get(accountsTotalsKey(idKey))
	if err != nil {
		return
	}
	err = protocol.Decode(encTotals, &totals)
	return
}

func kvPutAccountsTotals(kv kvWrite, idKey string, totals ledgercore.AccountTotals) error {
	return kv.Set(accountsTotalsKey(idKey), protocol.Encode(&totals))
}

// simulate "INSERT INTO assetcreators (asset, creator, ctype) VALUES (?, ?, ?)"
func kvInsertAssetCreators(kv kvWrite, cidx basics.CreatableIndex, ctype basics.CreatableType, creator []byte) error {
	return kv.Set(assetCreatorsKey(ctype, cidx), creator)
}

// simulate "DELETE FROM assetcreators WHERE asset=? AND ctype=?"
func kvDeleteAssetCreators(kv kvWrite, cidx basics.CreatableIndex, ctype basics.CreatableType) error {
	return kv.Delete(assetCreatorsKey(ctype, cidx))
}

type kvCreatableIterator struct {
	first      bool
	it         kvstore.Iterator
	snap       kvstore.Snapshot
	round      basics.Round
	cnt        uint64
	maxResults uint64
}

func (i *kvCreatableIterator) Err() error { return nil }
func (i *kvCreatableIterator) Close() error {
	i.it.Close()
	i.snap.Close()
	return nil
}

func (i *kvCreatableIterator) Next() bool {
	if i.first {
		i.first = false
	} else {
		i.it.Next()
	}
	// stop being valid after maxResults is met
	i.cnt++
	if i.cnt > i.maxResults {
		return false
	}
	return i.it.Valid()
}

func (i *kvCreatableIterator) Scan(args ...interface{}) error {
	// rnd *basics.Round, cidx *sql.NullInt64, creator *[]byte
	if len(args) != 3 {
		return fmt.Errorf("kvCreatableIterator Scan args should be 3, got %d", len(args))
	}
	argRnd := (args[0]).(*basics.Round)
	argCidx := (args[1]).(*sql.NullInt64)
	argBuf := (args[2]).(*[]byte)

	// already called Get on snapshot when creating iterator
	*argRnd = i.round

	ik := i.it.KeySlice()
	defer ik.Free()
	iv, err := i.it.ValueSlice()
	if err != nil {
		return err
	}
	defer iv.Free()
	_, cidx, err := splitAssetCreatorsKey(ik.Data())
	if err != nil {
		return err
	}
	*argCidx = sql.NullInt64{Int64: int64(cidx), Valid: true}
	creator := make([]byte, iv.Size())
	copy(creator[:], iv.Data())
	*argBuf = creator
	return nil
}

// simulate "SELECT rnd, asset, creator FROM acctrounds LEFT JOIN assetcreators ON assetcreators.asset <= ? AND assetcreators.ctype = ? WHERE acctrounds.id='acctbase' ORDER BY assetcreators.asset desc LIMIT ?"
func kvListCreatables(kv kvSnapshottableRead, maxIdx basics.CreatableIndex, maxResults uint64, ctype basics.CreatableType) (accountIterator, error) {
	// make read snapshot so that get for round number is consistent with iterator
	snap := kv.NewSnapshot()
	rnd, err := kvGetAccountRound(snap, "acctbase")
	if err != nil {
		return nil, err
	}
	// reverse iterate over range starting from "ctype + asset 0" to "ctype + asset maxIdx+1" (since end of range is not inclusive)
	iter := kv.NewIterator(
		assetCreatorsKey(ctype, basics.CreatableIndex(0)),
		assetCreatorsKey(ctype, basics.CreatableIndex(maxIdx+1)),
		true)
	return &kvCreatableIterator{
		first:      true,
		it:         iter,
		maxResults: maxResults,
		snap:       snap,
		round:      rnd,
	}, nil
}

// simulate "SELECT rnd, creator FROM acctrounds LEFT JOIN assetcreators ON asset = ? AND ctype = ? WHERE id='acctbase'"
func kvLookupCreator(kv kvMultiGet, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Round, []byte, error) {
	// atomic multiget of round number and creator data
	vals, err := kv.MultiGet([][]byte{accountRoundsKey("acctbase"), assetCreatorsKey(ctype, cidx)})
	if err != nil {
		return basics.Round(0), nil, err
	}
	if len(vals) != 2 {
		return basics.Round(0), nil, fmt.Errorf("kvLookupCreator vals len %d", len(vals))
	}
	return basics.Round(binary.BigEndian.Uint64(vals[0])), vals[1], nil
}
