// Copyright (C) 2019-2025 Algorand, Inc.
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

package driver

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/algorand/go-deadlock"
	"github.com/jmoiron/sqlx"
	"github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/daemon/kmd/wallet"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-codec/codec"
)

const (
	sqliteWalletDriverName      = "sqlite"
	sqliteWalletDriverVersion   = 1
	sqliteWalletsDirName        = "sqlite_wallets"
	sqliteWalletsDirPermissions = 0700
	sqliteWalletDBOptions       = "_secure_delete=on&_txlock=exclusive"
	sqliteMaxWalletNameLen      = 64
	sqliteMaxWalletIDLen        = 64
	sqliteIntOverflow           = 1 << 63
	sqliteWalletHasMnemonicUX   = false
	sqliteWalletHasMasterKey    = true
)

var sqliteWalletSupportedTxs = []protocol.TxType{protocol.PaymentTx, protocol.KeyRegistrationTx}
var disallowedFilenameRegex = regexp.MustCompile("[^a-zA-Z0-9_-]*")
var databaseFilenameRegex = regexp.MustCompile(`^.*\.db$`)

var walletSchema = `
CREATE TABLE IF NOT EXISTS metadata (
	driver_name TEXT NOT NULL,
	driver_version INT NOT NULL,
	wallet_id TEXT NOT NULL UNIQUE,
	wallet_name TEXT NOT NULL,
	mep_encrypted BLOB NOT NULL,
	mdk_encrypted BLOB NOT NULL,
	max_key_idx_encrypted BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
	address BLOB PRIMARY KEY,
	secret_key_encrypted BLOB NOT NULL,
	key_idx INT
);

CREATE TABLE IF NOT EXISTS msig_addrs (
	address BLOB PRIMARY KEY,
	version INT NOT NULL,
	threshold INT NOT NULL,
	pks BLOB NOT NULL
);
`

// SQLiteWalletDriver is the default wallet driver used by kmd. Keys are stored
// as authenticated-encrypted blobs in a sqlite 3 database.
type SQLiteWalletDriver struct {
	globalCfg config.KMDConfig
	sqliteCfg config.SQLiteWalletDriverConfig
	mux       *deadlock.Mutex

	claimedWallets [][][]byte
}

// SQLiteWallet represents a particular SQLiteWallet under the
// SQLiteWalletDriver
type SQLiteWallet struct {
	masterEncryptionKey  []byte
	masterDerivationKey  []byte
	walletPasswordSalt   [saltLen]byte
	walletPasswordHash   crypto.Digest
	walletPasswordHashed bool
	dbPath               string
	cfg                  config.SQLiteWalletDriverConfig
}

// The following msgpack codec interface was lifted from algod's network
// protocol code. We don't want to brick wallets when we change our network
// code, so we use our own version.
var codecHandle *codec.MsgpackHandle

// Initialize the codec
func init() {
	codecHandle = new(codec.MsgpackHandle)
	codecHandle.ErrorIfNoField = true
	codecHandle.ErrorIfNoArrayExpand = true
	codecHandle.Canonical = true
	codecHandle.RecursiveEmptyCheck = true
	codecHandle.WriteExt = true
	codecHandle.PositiveIntUnsigned = true
}

// interface{} => msgpack blob
func msgpackEncode(obj interface{}) []byte {
	var b []byte
	enc := codec.NewEncoderBytes(&b, codecHandle)
	enc.MustEncode(obj)
	return b
}

// msgpack blob => interface{}
func msgpackDecode(b []byte, objptr interface{}) error {
	dec := codec.NewDecoderBytes(b, codecHandle)
	return dec.Decode(objptr)
}

// InitWithConfig accepts a driver configuration so that the SQLite driver
// knows where to read and write its wallet databases
func (swd *SQLiteWalletDriver) InitWithConfig(cfg config.KMDConfig, log logging.Logger) error {
	swd.globalCfg = cfg
	swd.sqliteCfg = cfg.DriverConfig.SQLiteWalletDriverConfig

	// Make sure the scrypt params are reasonable
	if !swd.sqliteCfg.UnsafeScrypt {
		if swd.sqliteCfg.ScryptParams.ScryptN < minScryptN {
			return fmt.Errorf("slow scrypt N must be at least %d", minScryptN)
		}
		if swd.sqliteCfg.ScryptParams.ScryptR < minScryptR {
			return fmt.Errorf("slow scrypt R must be at least %d", minScryptR)
		}
		if swd.sqliteCfg.ScryptParams.ScryptP < minScryptP {
			return fmt.Errorf("slow scrypt P must be at least %d", minScryptP)
		}
	}

	// Make the wallets directory if it doesn't already exist
	err := swd.maybeMakeWalletsDir()
	if err != nil {
		return err
	}

	// Initialize lock. When creating a new wallet, this lock protects us from
	// creating another with the same name or ID
	swd.mux = &deadlock.Mutex{}

	return nil
}

// dbConnectionURL takes a path to a SQLite database on the filesystem and
// constructs a proper connection URL from it with feature flags included
func dbConnectionURL(path string) string {
	// Set flags on the database connection. For all options see:
	// https://github.com/mattn/go-sqlite3/blob/master/README.md#connection-string
	return fmt.Sprintf("file:%s?%s", path, sqliteWalletDBOptions)
}

// walletMetadataFromDB accepts a *sqlx.DB and extracts a wallet.Metadata from
// it
func walletMetadataFromDB(db *sqlx.DB) (metadata wallet.Metadata, err error) {
	var driverName string
	var walletID, walletName []byte
	var driverVersion uint32

	// Fetch the metadata to fill in a Metadata
	metadataRow := db.QueryRow("SELECT driver_name, driver_version, wallet_id, wallet_name FROM metadata LIMIT 1")
	err = metadataRow.Scan(&driverName, &driverVersion, &walletID, &walletName)
	if err != nil {
		err = errDatabase
		return
	}

	// Ensure this database is the correct version + driver
	if driverName != sqliteWalletDriverName {
		err = errWrongDriver
		return
	}
	if driverVersion != sqliteWalletDriverVersion {
		err = errWrongDriverVer
		return
	}

	// Build the Metadata
	metadata = wallet.Metadata{
		ID:                    walletID,
		Name:                  walletName,
		DriverName:            driverName,
		DriverVersion:         driverVersion,
		SupportsMnemonicUX:    sqliteWalletHasMnemonicUX,
		SupportsMasterKey:     sqliteWalletHasMasterKey,
		SupportedTransactions: sqliteWalletSupportedTxs,
	}

	return
}

// walletMetadataFromDBPath accepts path to a sqlite wallet database and
// returns a Metadata struct with information about it
func walletMetadataFromDBPath(dbPath string) (metadata wallet.Metadata, err error) {
	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(dbPath))
	if err != nil {
		err = errDatabaseConnect
		return
	}
	defer db.Close()
	return walletMetadataFromDB(db)
}

// potentialWalletPaths lists paths to plausible databases in the wallets
// directory. This means things that aren't directories and that match the
// databaseFilenameRegex
func (swd *SQLiteWalletDriver) potentialWalletPaths() (paths []string, err error) {
	// List all files and folders in the wallets directory
	wDir := swd.walletsDir()
	files, err := os.ReadDir(wDir)
	if err != nil {
		return
	}
	for _, f := range files {
		// Skip things that definitely aren't databases
		if f.IsDir() || !databaseFilenameRegex.Match([]byte(f.Name())) {
			continue
		}
		paths = append(paths, filepath.Join(wDir, f.Name()))
	}
	return
}

// ListWalletMetadatas opens everything that looks like a wallet in the
// walletsDir() and tries to extract its metadata. It does not fail if it
// is unable to read metadata from one of the files it attempts to open
func (swd *SQLiteWalletDriver) ListWalletMetadatas() (metadatas []wallet.Metadata, err error) {
	paths, err := swd.potentialWalletPaths()
	if err != nil {
		return
	}
	for _, path := range paths {
		// Ignore errors in case people dumped non-database files into this directory
		walletMetadata, err := walletMetadataFromDBPath(path)
		if err != nil {
			continue
		}
		metadatas = append(metadatas, walletMetadata)
	}
	return metadatas, nil
}

// findDBPathsById returns the paths to wallets with the specified id
func (swd *SQLiteWalletDriver) findDBPathsByID(id []byte) (paths []string, err error) {
	return swd.findDBPathsByField("ID", id)
}

// findDBPathsByName returns the paths to wallets with the specified name
func (swd *SQLiteWalletDriver) findDBPathsByName(name []byte) (paths []string, err error) {
	return swd.findDBPathsByField("Name", name)
}

// findDBPathsByField is a helper for findDBPathsByID and findDBPathsByName. It
// iterates over potential wallet databases and searches for the given
// testValue in the appropriate field
func (swd *SQLiteWalletDriver) findDBPathsByField(fieldName string, testValue []byte) (paths []string, err error) {
	potentialPaths, err := swd.potentialWalletPaths()
	if err != nil {
		return nil, err
	}
	for _, path := range potentialPaths {
		// Ignore errors in case people dumped non-database files into this directory
		walletMetadata, err := walletMetadataFromDBPath(path)
		if err != nil {
			continue
		}
		// Fetch the approriate field
		var fieldValue []byte
		switch fieldName {
		case "ID":
			fieldValue = walletMetadata.ID
		case "Name":
			fieldValue = walletMetadata.Name
		default:
			panic(fmt.Sprintf("unknown fieldName %s", fieldName))
		}
		// Check if there's a match
		if bytes.Equal(fieldValue, testValue) {
			paths = append(paths, path)
		}
	}
	return paths, nil
}

// maybeMakeWalletsDir tries to create the wallets directory if it doesn't
// already exist
func (swd SQLiteWalletDriver) maybeMakeWalletsDir() error {
	wDir := swd.walletsDir()
	err := os.Mkdir(wDir, sqliteWalletsDirPermissions)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("couldn't create wallets directory at %s: %v", wDir, err)
	}
	return nil
}

// walletsDir returns the wallet directory specified in the config, if there
// is one, otherwise it returns a subdirectory of the global kmd data dir
func (swd SQLiteWalletDriver) walletsDir() string {
	if swd.sqliteCfg.WalletsDir != "" {
		return swd.sqliteCfg.WalletsDir
	}
	return filepath.Join(swd.globalCfg.DataDir, sqliteWalletsDirName)
}

// nameIDToPath turns a wallet name and wallet id into a path to the
// corresponding database file to create
func (swd SQLiteWalletDriver) nameIDToPath(name []byte, id []byte) string {
	// It's OK if filtered names collide with each other, because ID is unique
	safeName := disallowedFilenameRegex.ReplaceAll(name, []byte(""))
	// wallet ID should already be safe, but filter it just in case
	safeID := disallowedFilenameRegex.ReplaceAll(id, []byte(""))

	var fileName string
	if bytes.Equal(safeName, safeID) {
		// If name and ID are equal, just use one of them
		fileName = fmt.Sprintf("%s.db", safeID)
	} else {
		// Otherwise, append them
		fileName = fmt.Sprintf("%s.%s.db", safeName, safeID)
	}

	// Append to dataDir
	return filepath.Join(swd.walletsDir(), fileName)
}

// checkDBError inspects an error from the database and interprets it as a
// "duplicate key" error, a generic database error, or a nil error
func checkDBError(err error) error {
	if err != nil {
		serr, ok := err.(sqlite3.Error)
		if ok && serr.Code == sqlite3.ErrConstraint {
			// If it was a constraint error, that means we already have the key.
			return errKeyExists
		}
		// Otherwise, return a generic database error
		return errDatabase
	}
	return nil
}

func (swd *SQLiteWalletDriver) claimWalletNameID(name []byte, id []byte) (dbPath string, err error) {
	// Grab our lock to avoid races with duplicate wallet names/ids
	swd.mux.Lock()
	defer swd.mux.Unlock()

	for _, nameID := range swd.claimedWallets {
		if bytes.Equal(nameID[0], name) {
			return "", errSameName
		}
		if bytes.Equal(nameID[1], id) {
			return "", errSameID
		}
	}

	// name, id -> "/data/dir/name-id.db"
	dbPath = swd.nameIDToPath(name, id)

	// Ensure the wallet with this filename doesn't already exist, and that we
	// have permissions to access the wallet directory
	_, err = os.Stat(dbPath)
	if !os.IsNotExist(err) {
		return
	}

	// Ensure a wallet with this name doesn't already exist. swd.mux is
	// locked above to avoid races here
	sameNameDBPaths, err := swd.findDBPathsByName(name)
	if err != nil {
		return
	}
	if len(sameNameDBPaths) != 0 {
		return "", errSameName
	}

	// Ensure a wallet with this id doesn't already exist. As above, we use
	// swd.mux to avoid races
	sameIDDBPaths, err := swd.findDBPathsByID(id)
	if err != nil {
		return
	}
	if len(sameIDDBPaths) != 0 {
		return "", errSameID
	}

	swd.claimedWallets = append(swd.claimedWallets, [][]byte{name, id})
	return
}

// CreateWallet ensures that a wallet of the given name/id combo doesn't exist,
// and initializes a database with the appropriate name.
func (swd *SQLiteWalletDriver) CreateWallet(name []byte, id []byte, pw []byte, mdk crypto.MasterDerivationKey) error {
	if len(name) > sqliteMaxWalletNameLen {
		return errNameTooLong
	}

	if len(id) > sqliteMaxWalletIDLen {
		return errIDTooLong
	}

	dbPath, err := swd.claimWalletNameID(name, id)
	if err != nil {
		return err
	}
	// TODO? drop the entry in swd.claimedWallets on exit?

	// Create the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(dbPath))
	if err != nil {
		return errDatabaseConnect
	}
	defer db.Close()

	// Run the schema
	_, err = db.Exec(walletSchema)
	if err != nil {
		return errDatabase
	}

	// Generate the master encryption password, used to encrypt the master
	// derivation key, generated keys, and imported keys
	var masterKey [masterKeyLen]byte
	err = fillRandomBytes(masterKey[:])
	if err != nil {
		return err
	}

	// If we were passed a blank master derivation key, generate one here
	masterDerivationKey := mdk
	if masterDerivationKey == (crypto.MasterDerivationKey{}) {
		err = fillRandomBytes(masterDerivationKey[:])
		if err != nil {
			return err
		}
	}

	// Encrypt the master encryption password using the user's password (which
	// may be blank)
	encryptedMEPBlob, err := encryptBlobWithPasswordBlankOK(masterKey[:], PTMasterKey, pw, &swd.sqliteCfg.ScryptParams)
	if err != nil {
		return err
	}

	// Encrypt the master derivation key using the master encryption password
	// (which may not be blank)
	encryptedMDKBlob, err := encryptBlobWithKey(masterDerivationKey[:], PTMasterDerivationKey, masterKey[:])
	if err != nil {
		return err
	}

	// Encrypt the max key index using the master encryption password. We encrypt
	// this for integrity reasons, so that someone with access to the file can't
	// make the index enormous.
	maxKeyIdx := 0
	encryptedIdxBlob, err := encryptBlobWithKey(msgpackEncode(maxKeyIdx), PTMaxKeyIdx, masterKey[:])
	if err != nil {
		return err
	}

	// Store the metadata row in the database
	_, err = db.Exec("INSERT INTO metadata (driver_name, driver_version, wallet_id, wallet_name, mep_encrypted, mdk_encrypted, max_key_idx_encrypted) VALUES(?, ?, ?, ?, ?, ?, ?)", sqliteWalletDriverName, sqliteWalletDriverVersion, id, name, encryptedMEPBlob, encryptedMDKBlob, encryptedIdxBlob)
	if err != nil {
		return errDatabase
	}

	return nil
}

// FetchWallet looks up a wallet by ID and returns it, failing if there's more
// than one wallet with the given ID
func (swd *SQLiteWalletDriver) FetchWallet(id []byte) (sqWallet wallet.Wallet, err error) {
	swd.mux.Lock()
	defer swd.mux.Unlock()
	return swd.fetchWalletLocked(id)
}

// fetchWalletLocked is the guts of FetchWallet. Precondition: we must hold
// swd.mux
func (swd *SQLiteWalletDriver) fetchWalletLocked(id []byte) (sqWallet wallet.Wallet, err error) {
	// We want to allow users to drop in database files from other systems and
	// potentially rename the file, so we iterate over the wallet files instead
	// of looking up what we would have named them to begin with.
	dbPaths, err := swd.findDBPathsByID(id)
	if err != nil {
		return
	}

	// Do we have this wallet?
	if len(dbPaths) == 0 {
		err = errWalletNotFound
		return
	}

	// Ensure only one wallet has this ID
	if len(dbPaths) > 1 {
		err = errIDConflict
		return
	}

	// Connect to the database
	dbPath := dbPaths[0]
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(dbPath))
	if err != nil {
		err = errDatabaseConnect
		return
	}
	defer db.Close()

	// Fill in the wallet details
	sqWallet = &SQLiteWallet{
		masterEncryptionKey: nil,
		masterDerivationKey: nil,
		dbPath:              dbPath,
		cfg:                 swd.sqliteCfg,
	}
	return
}

// RenameWallet renames the wallet with the given id to newName. It does not
// rename the database file itself, because doing so safely is tricky
func (swd *SQLiteWalletDriver) RenameWallet(newName []byte, id []byte, pw []byte) error {
	// Grab a lock so our duplicate names check can't race
	swd.mux.Lock()
	defer swd.mux.Unlock()

	// Ensure a wallet with this name doesn't already exist
	sameNameDBPaths, err := swd.findDBPathsByName(newName)
	if err != nil {
		return err
	}
	if len(sameNameDBPaths) != 0 {
		return errSameName
	}

	// Fetch the wallet
	curWallet, err := swd.fetchWalletLocked(id)
	if err != nil {
		return err
	}
	sqWallet, ok := curWallet.(*SQLiteWallet)
	if !ok {
		return errSQLiteWrongType
	}

	// Check the password
	err = sqWallet.CheckPassword(pw)
	if err != nil {
		return err
	}

	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sqWallet.dbPath))
	if err != nil {
		return errDatabaseConnect
	}
	defer db.Close()

	// Update the metadata row
	_, err = db.Exec("UPDATE metadata SET wallet_name=? WHERE wallet_id=?", newName, id)
	if err != nil {
		return errDatabase
	}

	return nil
}

// Metadata builds a wallet.Metadata from our metadata table
func (sw *SQLiteWallet) Metadata() (meta wallet.Metadata, err error) {
	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sw.dbPath))
	if err != nil {
		err = errDatabaseConnect
		return
	}
	defer db.Close()

	return walletMetadataFromDB(db)
}

// decryptAndGetMasterKey fetches the master key from the metadata table and
// attempts to decrypt it with the passed password
func (sw *SQLiteWallet) decryptAndGetMasterKey(pw []byte) ([]byte, error) {
	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sw.dbPath))
	if err != nil {
		return nil, errDatabaseConnect
	}
	defer db.Close()

	var encryptedMEPBlob []byte
	err = db.Get(&encryptedMEPBlob, "SELECT mep_encrypted FROM metadata LIMIT 1")
	if err != nil {
		return nil, errDatabase
	}

	mep, err := decryptBlobWithPassword(encryptedMEPBlob, PTMasterKey, pw)
	if err != nil {
		return nil, err
	}

	return mep, nil
}

// decryptAndGetMasterDerivationKey fetches the mdk from the metadata table and
// attempts to decrypt it with the master password
func (sw *SQLiteWallet) decryptAndGetMasterDerivationKey(pw []byte) ([]byte, error) {
	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sw.dbPath))
	if err != nil {
		return nil, errDatabaseConnect
	}
	defer db.Close()

	var encryptedMDKBlob []byte
	err = db.Get(&encryptedMDKBlob, "SELECT mdk_encrypted FROM metadata LIMIT 1")
	if err != nil {
		return nil, errDatabase
	}

	mdk, err := decryptBlobWithPassword(encryptedMDKBlob, PTMasterDerivationKey, pw)
	if err != nil {
		return nil, err
	}

	return mdk, nil
}

// Init attempts to decrypt the master encrypt password and master derivation
// key, and store them in memory for subsequent operations
func (sw *SQLiteWallet) Init(pw []byte) error {
	// Decrypt the master password
	masterEncryptionKey, err := sw.decryptAndGetMasterKey(pw)
	if err != nil {
		return err
	}

	// Decrypt the master derivation key
	masterDerivationKey, err := sw.decryptAndGetMasterDerivationKey(masterEncryptionKey)
	if err != nil {
		return err
	}

	// Initialize wallet
	sw.masterEncryptionKey = masterEncryptionKey
	sw.masterDerivationKey = masterDerivationKey
	err = fillRandomBytes(sw.walletPasswordSalt[:])
	if err != nil {
		return err
	}
	sw.walletPasswordHash = fastHashWithSalt(pw, sw.walletPasswordSalt[:])
	sw.walletPasswordHashed = true
	return nil
}

// CheckPassword checks that the database can be decrypted with the password.
// It's the same as Init but doesn't store the decrypted key
func (sw *SQLiteWallet) CheckPassword(pw []byte) error {
	if sw.walletPasswordHashed {
		// Check against pre-computed password hash
		pwhash := fastHashWithSalt(pw, sw.walletPasswordSalt[:])
		if subtle.ConstantTimeCompare(pwhash[:], sw.walletPasswordHash[:]) == 1 {
			return nil
		}
		return errDecrypt
	}

	_, err := sw.decryptAndGetMasterKey(pw)
	return err
}

// ListKeys lists all the addresses in the wallet
func (sw *SQLiteWallet) ListKeys() (addrs []crypto.Digest, err error) {
	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sw.dbPath))
	if err != nil {
		return nil, errDatabaseConnect
	}
	defer db.Close()

	var addrByteSlices [][]byte
	var tmp crypto.Digest
	// We can't select directly into a crypto.Digest array, unfortunately.
	// Instead, we select into a slice of byte slices, and then convert each of
	// those slices into a crypto.Digest.
	err = db.Select(&addrByteSlices, "SELECT address FROM keys")
	if err != nil {
		err = errDatabase
		return
	}

	for _, byteSlice := range addrByteSlices {
		copy(tmp[:], byteSlice)
		addrs = append(addrs, tmp)
	}

	return
}

// ExportMasterDerivationKey decrypts the encrypted MDK and returns it
func (sw *SQLiteWallet) ExportMasterDerivationKey(pw []byte) (mdk crypto.MasterDerivationKey, err error) {
	// Check the password
	err = sw.CheckPassword(pw)
	if err != nil {
		return
	}

	// Copy master derivation key into the result
	copy(mdk[:], sw.masterDerivationKey)
	return
}

// ImportKey imports a keypair into the wallet, deriving the public key from
// the passed secret key
func (sw *SQLiteWallet) ImportKey(rawSK crypto.PrivateKey) (addr crypto.Digest, err error) {
	// Extract the seed from the secret key so that we don't trust the public part
	seed, err := crypto.SecretKeyToSeed(rawSK)
	if err != nil {
		err = errSKToPK
		return
	}

	// Convert the seed to an sk/pk pair
	sigSecrets := crypto.GenerateSignatureSecrets(seed)
	pk, sk := sigSecrets.SignatureVerifier, sigSecrets.SK

	// Encrypt the encoded secret key
	skEncrypted, err := encryptBlobWithKey(msgpackEncode(sk), PTSecretKey, sw.masterEncryptionKey)
	if err != nil {
		return
	}

	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sw.dbPath))
	if err != nil {
		err = errDatabaseConnect
		return
	}
	defer db.Close()

	// Insert the pk, e(sk) into the database
	addr = publicKeyToAddress(pk)
	_, err = db.Exec("INSERT INTO keys (address, secret_key_encrypted) VALUES(?, ?)", addr[:], skEncrypted)
	err = checkDBError(err)
	if err != nil {
		return
	}
	return
}

// ExportKey fetches the encrypted private key using the public key, decrypts
// it, verifies that it matches the passed public key, and returns it
func (sw *SQLiteWallet) ExportKey(addr crypto.Digest, pw []byte) (sk crypto.PrivateKey, err error) {
	// Check the password
	err = sw.CheckPassword(pw)
	if err != nil {
		return
	}

	// Export the key
	return sw.fetchSecretKey(addr)
}

// fetchSecretKey retrieves the private key for a given public key
func (sw *SQLiteWallet) fetchSecretKey(addr crypto.Digest) (sk crypto.PrivateKey, err error) {
	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sw.dbPath))
	if err != nil {
		err = errDatabaseConnect
		return
	}
	defer db.Close()

	var skCandidate crypto.PrivateKey
	var blob []byte

	// Fetch the encrypted secret key from the database
	err = db.Get(&blob, "SELECT secret_key_encrypted FROM keys WHERE address=?", addr[:])
	if err != nil {
		err = errKeyNotFound
		return
	}

	// Decrypt the secret key
	skEncoded, err := decryptBlobWithPassword(blob, PTSecretKey, sw.masterEncryptionKey)
	if err != nil {
		return
	}

	// Decode the secret key candidate
	err = msgpackDecode(skEncoded, &skCandidate)
	if err != nil {
		return
	}

	// Extract the public key from the candidate secret key
	derivedPK, err := crypto.SecretKeyToPublicKey(skCandidate)
	if err != nil {
		err = errSKToPK
		return
	}

	// Convert the derived public key to an address
	derivedAddr := publicKeyToAddress(derivedPK)

	// Ensure the derived address matches the one we used to look the key up
	if addr != derivedAddr {
		err = errTampering
		return
	}

	// The candidate looks good, return it
	sk = skCandidate
	return
}

// GenerateKey generates a key from system entropy and imports it
func (sw *SQLiteWallet) GenerateKey(displayMnemonic bool) (addr crypto.Digest, err error) {
	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sw.dbPath))
	if err != nil {
		err = errDatabaseConnect
		return
	}
	defer db.Close()

	// The sqlite wallet has SupportsMnemonicUX = false, meaning we don't know how to
	// show mnemonics to the user
	if displayMnemonic {
		err = errNoMnemonicUX
		return
	}

	// Begin an exclusive database transaction (we set _txlock=exclusive on the
	// database connection string)
	tx, err := db.Beginx()
	if err != nil {
		err = errDatabase
		return
	}

	// Generate and insert the next key
	addr, err = sw.generateKeyTxLocked(tx)
	if err != nil {
		// Rollback in case any part of the tx failed
		tx.Rollback()
		return
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		err = errDatabase
		return
	}

	return addr, nil
}

// generateKeyTxLocked is a helper for GenerateKey that accepts a locked tx,
// computes the next key that should be generated, inserts it, and returns
// its address
func (sw *SQLiteWallet) generateKeyTxLocked(tx *sqlx.Tx) (addr crypto.Digest, err error) {
	// Fetch the encrypted highest index
	var encryptedHighestIndexBlob []byte
	err = tx.Get(&encryptedHighestIndexBlob, "SELECT max_key_idx_encrypted FROM metadata LIMIT 1")
	if err != nil {
		err = errDatabase
		return
	}

	// Decrypt the highest index
	highestIndexBlob, err := decryptBlobWithPassword(encryptedHighestIndexBlob, PTMaxKeyIdx, sw.masterEncryptionKey)
	if err != nil {
		return
	}

	// Decode the highest index
	var highestIndex uint64
	err = msgpackDecode(highestIndexBlob, &highestIndex)
	if err != nil {
		return
	}

	// nextIndex is the index of the next key we should generate
	nextIndex := highestIndex + 1

	var genPK crypto.PublicKey
	var genSK crypto.PrivateKey
	var genAddr crypto.Digest

	// We may have to bump nextIndex if the user has manually imported the next
	// key we were going to generate (thus we didn't see it in the search for the
	// highest-derived key above)
	for {
		// Honestly, if you could get 2**63 - 1 keys into this database, I'd be impressed
		if nextIndex == sqliteIntOverflow {
			err = errTooManyKeys
			return
		}

		// Compute the secret key and public key for nextIndex
		genPK, genSK, err = extractKeyWithIndex(sw.masterDerivationKey, nextIndex)
		if err != nil {
			return
		}

		// Convert the public key into an address
		genAddr = publicKeyToAddress(genPK)

		// Check that we don't already have this PK in the database
		var cnt int
		err = tx.Get(&cnt, "SELECT COUNT(1) FROM keys WHERE address=?", genAddr[:])
		if err != nil {
			err = errDatabase
			return
		}

		if cnt == 0 {
			// Good, key didn't exist. Break from loop
			break
		}

		// Uh oh, user already imported this key manually. Bump nextIndex
		nextIndex++
	}

	// Encrypt the encoded secret key
	skEncrypted, err := encryptBlobWithKey(msgpackEncode(genSK), PTSecretKey, sw.masterEncryptionKey)
	if err != nil {
		return
	}

	// Insert the key into the database
	_, err = tx.Exec("INSERT INTO keys (address, secret_key_encrypted, key_idx) VALUES(?, ?, ?)", genAddr[:], skEncrypted, nextIndex)
	if err != nil {
		return
	}

	// Encrypt the new max key index
	encryptedIdxBlob, err := encryptBlobWithKey(msgpackEncode(nextIndex), PTMaxKeyIdx, sw.masterEncryptionKey)
	if err != nil {
		return
	}

	// Update the metadata row
	_, err = tx.Exec("UPDATE metadata SET max_key_idx_encrypted = ?", encryptedIdxBlob)
	if err != nil {
		return
	}

	// Return the generated public key
	return genAddr, nil
}

// DeleteKey deletes the key corresponding to the passed public key from the wallet
func (sw *SQLiteWallet) DeleteKey(addr crypto.Digest, pw []byte) (err error) {
	// Check the password
	err = sw.CheckPassword(pw)
	if err != nil {
		return
	}

	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sw.dbPath))
	if err != nil {
		return errDatabaseConnect
	}
	defer db.Close()

	// Delete the key
	_, err = db.Exec("DELETE FROM keys WHERE address=?", addr[:])
	if err != nil {
		err = errDatabase
	}
	return
}

// ImportMultisigAddr imports a multisig address, taking in version, threshold,
// and public keys
func (sw *SQLiteWallet) ImportMultisigAddr(version, threshold uint8, pks []crypto.PublicKey) (addr crypto.Digest, err error) {
	addr, err = crypto.MultisigAddrGen(version, threshold, pks)
	if err != nil {
		return
	}

	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sw.dbPath))
	if err != nil {
		err = errDatabaseConnect
		return
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO msig_addrs (address, version, threshold, pks) VALUES (?, ?, ?, ?)", addr[:], version, threshold, msgpackEncode(pks))
	err = checkDBError(err)
	if err != nil {
		return
	}
	return
}

// LookupMultisigPreimage exports the preimage of a multisig address: version,
// threshold, public keys
func (sw *SQLiteWallet) LookupMultisigPreimage(addr crypto.Digest) (version, threshold uint8, pks []crypto.PublicKey, err error) {
	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sw.dbPath))
	if err != nil {
		err = errDatabaseConnect
		return
	}
	defer db.Close()

	var pksCandidate []crypto.PublicKey
	var versionCandidate, thresholdCandidate int
	var pksBlob []byte

	row := db.QueryRow("SELECT version, threshold, pks FROM msig_addrs WHERE address=?", addr[:])
	err = row.Scan(&versionCandidate, &thresholdCandidate, &pksBlob)
	if err != nil {
		err = errMsigDataNotFound
		return
	}

	// Decode the candidate
	err = msgpackDecode(pksBlob, &pksCandidate)
	if err != nil {
		return
	}

	// Sanity check: make sure the preimage is correct
	addr2, err := crypto.MultisigAddrGen(uint8(versionCandidate), uint8(thresholdCandidate), pksCandidate)
	if addr2 != addr {
		err = errTampering
		return
	}

	version = uint8(versionCandidate)
	threshold = uint8(thresholdCandidate)
	pks = pksCandidate
	return
}

// DeleteMultisigAddr deletes the multisig address and preimage from the database
func (sw *SQLiteWallet) DeleteMultisigAddr(addr crypto.Digest, pw []byte) (err error) {
	// Check the password
	err = sw.CheckPassword(pw)
	if err != nil {
		return
	}

	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sw.dbPath))
	if err != nil {
		return errDatabaseConnect
	}
	defer db.Close()

	_, err = db.Exec("DELETE FROM msig_addrs WHERE address=?", addr[:])
	if err != nil {
		err = errDatabase
	}
	return
}

// ListMultisigAddrs lists the multisig addresses whose preimages we know
func (sw *SQLiteWallet) ListMultisigAddrs() (addrs []crypto.Digest, err error) {
	// Connect to the database
	db, err := sqlx.Connect("sqlite3", dbConnectionURL(sw.dbPath))
	if err != nil {
		err = errDatabaseConnect
		return
	}
	defer db.Close()

	var addrByteSlices [][]byte
	var tmp crypto.Digest
	err = db.Select(&addrByteSlices, "SELECT address FROM msig_addrs")
	if err != nil {
		err = errDatabase
		return
	}
	for _, addr := range addrByteSlices {
		copy(tmp[:], addr)
		addrs = append(addrs, tmp)
	}
	return
}

// SignTransaction signs the passed transaction with the private key whose public key is provided, or
// if the provided public key is zero, inferring the required private key from the transaction itself
func (sw *SQLiteWallet) SignTransaction(tx transactions.Transaction, pk crypto.PublicKey, pw []byte) (stx []byte, err error) {
	// Check the password
	err = sw.CheckPassword(pw)
	if err != nil {
		return
	}

	// Fetch the required key
	var sk crypto.PrivateKey
	if (pk == crypto.PublicKey{}) {
		sk, err = sw.fetchSecretKey(crypto.Digest(tx.Src()))
	} else {
		sk, err = sw.fetchSecretKey(crypto.Digest(pk))
	}
	if err != nil {
		return
	}

	// Generate the signature secrets
	secrets, err := crypto.SecretKeyToSignatureSecrets(sk)
	if err != nil {
		err = errSKToPK
		return
	}

	// Sign the transaction
	stxn := tx.Sign(secrets)
	stx = protocol.Encode(&stxn)
	return
}

// SignProgram signs the passed data for the src address
func (sw *SQLiteWallet) SignProgram(data []byte, src crypto.Digest, pw []byte) (stx []byte, err error) {
	// Check the password
	err = sw.CheckPassword(pw)
	if err != nil {
		return
	}

	// Fetch the required key
	sk, err := sw.fetchSecretKey(crypto.Digest(src))
	if err != nil {
		return
	}

	// Generate the signature secrets
	secrets, err := crypto.SecretKeyToSignatureSecrets(sk)
	if err != nil {
		err = errSKToPK
		return
	}

	progb := logic.Program(data)
	// Sign the transaction
	sig := secrets.Sign(&progb)
	stx = sig[:]
	return
}

// MultisigSignTransaction starts a multisig signature or adds a signature to a
// partially signed multisig transaction signature of the passed transaction
// using the key
func (sw *SQLiteWallet) MultisigSignTransaction(tx transactions.Transaction, pk crypto.PublicKey, partial crypto.MultisigSig, pw []byte, signer crypto.Digest) (sig crypto.MultisigSig, err error) {
	// Check the password
	err = sw.CheckPassword(pw)
	if err != nil {
		return
	}

	if partial.Version == 0 && partial.Threshold == 0 && len(partial.Subsigs) == 0 {
		// We weren't given a partial multisig, so create a new one

		// Look up the preimage in the database
		var pks []crypto.PublicKey
		var version, threshold uint8
		version, threshold, pks, err = sw.LookupMultisigPreimage(crypto.Digest(tx.Src()))
		if err != nil {
			return
		}

		// Fetch the required secret key
		var sk crypto.PrivateKey
		sk, err = sw.fetchSecretKey(publicKeyToAddress(pk))
		if err != nil {
			return
		}

		// Convert the secret key to crypto.SignatureSecrets
		var secrets *crypto.SignatureSecrets
		secrets, err = crypto.SecretKeyToSignatureSecrets(sk)
		if err != nil {
			err = errSKToPK
			return
		}

		// Sign the transaction
		from := crypto.Digest(tx.Src())
		sig, err = crypto.MultisigSign(tx, from, version, threshold, pks, *secrets)
		return
	}

	// We were given a partial multisig, so add to it

	// Check preimage matches tx src address
	var addr crypto.Digest
	addr, err = crypto.MultisigAddrGenWithSubsigs(partial.Version, partial.Threshold, partial.Subsigs)
	if err != nil {
		return
	}

	// Check that the multisig address equals to either sender or signer
	if addr != crypto.Digest(tx.Src()) && addr != signer {
		err = errMsigWrongAddr
		return
	}

	// Check that key is one of the ones in the preimage
	err = errMsigWrongKey
	for _, subsig := range partial.Subsigs {
		if pk == subsig.Key {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}

	// Fetch the required secret key
	sk, err := sw.fetchSecretKey(publicKeyToAddress(pk))
	if err != nil {
		return
	}

	// Convert the secret key to crypto.SignatureSecrets
	secrets, err := crypto.SecretKeyToSignatureSecrets(sk)
	if err != nil {
		return
	}

	// Sign the transaction, and merge the multisig into the partial
	version, threshold, pks := partial.Preimage()
	msig2, err := crypto.MultisigSign(tx, addr, version, threshold, pks, *secrets)
	if err != nil {
		return
	}
	sig, err = crypto.MultisigMerge(partial, msig2)
	return
}

// MultisigSignProgram starts a multisig signature or adds a signature to a
// partially signed multisig transaction signature of the passed transaction
// using the key
func (sw *SQLiteWallet) MultisigSignProgram(data []byte, src crypto.Digest, pk crypto.PublicKey, partial crypto.MultisigSig, pw []byte, useLegacyMsig bool) (sig crypto.MultisigSig, err error) {
	// Check the password
	err = sw.CheckPassword(pw)
	if err != nil {
		return
	}

	if partial.Version == 0 && partial.Threshold == 0 && len(partial.Subsigs) == 0 {
		// We weren't given a partial multisig, so create a new one

		// Look up the preimage in the database
		var pks []crypto.PublicKey
		var version, threshold uint8
		version, threshold, pks, err = sw.LookupMultisigPreimage(src)
		if err != nil {
			return
		}

		// Fetch the required secret key
		var sk crypto.PrivateKey
		sk, err = sw.fetchSecretKey(publicKeyToAddress(pk))
		if err != nil {
			return
		}

		// Convert the secret key to crypto.SignatureSecrets
		var secrets *crypto.SignatureSecrets
		secrets, err = crypto.SecretKeyToSignatureSecrets(sk)
		if err != nil {
			err = errSKToPK
			return
		}

		// Sign the program
		from := src
		if useLegacyMsig {
			sig, err = crypto.MultisigSign(logic.Program(data), from, version, threshold, pks, *secrets)
		} else {
			sig, err = crypto.MultisigSign(logic.MultisigProgram{Addr: from, Program: data}, from, version, threshold, pks, *secrets)
		}
		return
	}

	// We were given a partial multisig, so add to it

	// Check preimage matches tx src address
	var addr crypto.Digest
	addr, err = crypto.MultisigAddrGenWithSubsigs(partial.Version, partial.Threshold, partial.Subsigs)
	if err != nil {
		return
	}
	if addr != src {
		err = errMsigWrongAddr
		return
	}

	// Check that key is one of the ones in the preimage
	err = errMsigWrongKey
	for _, subsig := range partial.Subsigs {
		if pk == subsig.Key {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}

	// Fetch the required secret key
	sk, err := sw.fetchSecretKey(publicKeyToAddress(pk))
	if err != nil {
		return
	}

	// Convert the secret key to crypto.SignatureSecrets
	secrets, err := crypto.SecretKeyToSignatureSecrets(sk)
	if err != nil {
		return
	}

	// Sign the program and merge the multisig into the partial
	version, threshold, pks := partial.Preimage()
	var msig2 crypto.MultisigSig
	if useLegacyMsig {
		msig2, err = crypto.MultisigSign(logic.Program(data), addr, version, threshold, pks, *secrets)
	} else {
		msig2, err = crypto.MultisigSign(logic.MultisigProgram{Addr: addr, Program: data}, addr, version, threshold, pks, *secrets)
	}
	if err != nil {
		return
	}
	sig, err = crypto.MultisigMerge(partial, msig2)
	return
}
