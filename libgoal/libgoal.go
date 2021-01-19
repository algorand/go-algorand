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

package libgoal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	algodclient "github.com/algorand/go-algorand/daemon/algod/api/client"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	kmdclient "github.com/algorand/go-algorand/daemon/kmd/client"
	"github.com/algorand/go-algorand/rpcs"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/common"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
)

// defaultKMDTimeoutSecs is the default number of seconds after which kmd will
// kill itself if there are no requests. This can be overridden with
// SetKMDStartArgs
const defaultKMDTimeoutSecs = 60

// DefaultKMDDataDir is the name of the directory within the algod data directory where kmd data goes
const DefaultKMDDataDir = nodecontrol.DefaultKMDDataDir

// Client represents the entry point for all libgoal functions
type Client struct {
	nc                   nodecontrol.NodeController
	kmdStartArgs         nodecontrol.KMDStartArgs
	dataDir              string
	cacheDir             string
	consensus            config.ConsensusProtocols
	algodVersionAffinity algodclient.APIVersion
	kmdVersionAffinity   kmdclient.APIVersion
}

// ClientConfig is data to configure a Client
type ClientConfig struct {
	// AlgodDataDir is the data dir for `algod`
	AlgodDataDir string

	// KMDDataDir is the data dir for `kmd`, default ${HOME}/.algorand/kmd
	KMDDataDir string

	// CacheDir is a place to store some stuff
	CacheDir string

	// BinDir may be "" and it will be guesed
	BinDir string
}

// ClientType represents the type of client you need
// It ensures the specified type(s) can be initialized
// when the libgoal client is created.
// Any client type not specified will be initialized on-demand.
type ClientType int

const (
	// DynamicClient creates clients on-demand
	DynamicClient ClientType = iota
	// KmdClient ensures the kmd client can be initialized when created
	KmdClient
	// AlgodClient ensures the algod client can be initialized when created
	AlgodClient
	// FullClient ensures all clients can be initialized when created
	FullClient
)

// MakeClientWithBinDir creates and inits a libgoal.Client, additionally
// allowing the user to specify a binary directory
func MakeClientWithBinDir(binDir, dataDir, cacheDir string, clientType ClientType) (c Client, err error) {
	config := ClientConfig{
		BinDir:       binDir,
		AlgodDataDir: dataDir,
		CacheDir:     cacheDir,
	}
	err = c.init(config, clientType)
	return
}

// MakeClient creates and inits a libgoal.Client
func MakeClient(dataDir, cacheDir string, clientType ClientType) (c Client, err error) {
	binDir, err := util.ExeDir()
	if err != nil {
		return
	}
	config := ClientConfig{
		BinDir:       binDir,
		AlgodDataDir: dataDir,
		CacheDir:     cacheDir,
	}
	err = c.init(config, clientType)
	return
}

// MakeClientFromConfig creates a libgoal.Client from a config struct with many options.
func MakeClientFromConfig(config ClientConfig, clientType ClientType) (c Client, err error) {
	if config.BinDir == "" {
		config.BinDir, err = util.ExeDir()
		if err != nil {
			return
		}
	}
	err = c.init(config, clientType)
	return
}

// Init takes data directory path or an empty string if $ALGORAND_DATA is defined and initializes Client
func (c *Client) init(config ClientConfig, clientType ClientType) error {
	// check and assign dataDir
	dataDir, err := getDataDir(config.AlgodDataDir)
	if err != nil {
		return err
	}
	c.dataDir = dataDir
	c.cacheDir = config.CacheDir
	c.algodVersionAffinity = algodclient.APIVersionV1
	c.kmdVersionAffinity = kmdclient.APIVersionV1

	// Get node controller
	nc, err := getNodeController(config.BinDir, config.AlgodDataDir)
	if err != nil {
		return err
	}
	if config.KMDDataDir != "" {
		nc.SetKMDDataDir(config.KMDDataDir)
	} else {
		algodKmdPath, _ := filepath.Abs(filepath.Join(dataDir, DefaultKMDDataDir))
		nc.SetKMDDataDir(algodKmdPath)
	}
	c.nc = nc

	// Initialize default kmd start args
	c.kmdStartArgs = nodecontrol.KMDStartArgs{
		TimeoutSecs: defaultKMDTimeoutSecs,
	}

	if clientType == KmdClient || clientType == FullClient {
		_, err = c.ensureKmdClient()
		if err != nil {
			return err
		}
	}

	if clientType == AlgodClient || clientType == FullClient {
		_, err = c.ensureAlgodClient()
		if err != nil {
			return err
		}
	}

	c.consensus, err = nc.GetConsensus()
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) ensureKmdClient() (*kmdclient.KMDClient, error) {
	kmd, err := c.getKMDClient()
	if err != nil {
		return nil, err
	}
	return &kmd, nil
}

func (c *Client) ensureAlgodClient() (*algodclient.RestClient, error) {
	algod, err := c.getAlgodClient()
	if err != nil {
		return nil, err
	}
	algod.SetAPIVersionAffinity(c.algodVersionAffinity)
	return &algod, err
}

// DataDir returns the Algorand's client data directory path
func (c *Client) DataDir() string {
	return c.dataDir
}

func getDataDir(dataDir string) (string, error) {
	// Get the target data directory to work against,
	// then handle the scenario where no data directory is provided.

	// Figure out what data directory to tell algod to use.
	// If not specified on cmdline with '-d', look for default in environment.
	dir := dataDir
	if dir == "" {
		dir = os.Getenv("ALGORAND_DATA")
	}
	if dir == "" {
		fmt.Println(errorNoDataDirectory.Error())
		return "", errorNoDataDirectory

	}
	return dir, nil
}

func getNodeController(binDir, dataDir string) (nc nodecontrol.NodeController, err error) {
	dataDir, err = getDataDir(dataDir)
	if err != nil {
		return nodecontrol.NodeController{}, nil
	}

	return nodecontrol.MakeNodeController(binDir, dataDir), nil
}

// SetKMDStartArgs sets the arguments used when starting kmd
func (c *Client) SetKMDStartArgs(args nodecontrol.KMDStartArgs) {
	c.kmdStartArgs = args
}

func (c *Client) getKMDClient() (kmdclient.KMDClient, error) {
	// Will return alreadyRunning = true if kmd already running
	_, err := c.nc.StartKMD(c.kmdStartArgs)
	if err != nil {
		return kmdclient.KMDClient{}, err
	}

	kmdClient, err := c.nc.KMDClient()
	if err != nil {
		return kmdclient.KMDClient{}, err
	}
	return kmdClient, nil
}

func (c *Client) getAlgodClient() (algodclient.RestClient, error) {
	algodClient, err := c.nc.AlgodClient()
	if err != nil {
		return algodclient.RestClient{}, err
	}
	return algodClient, nil
}

func (c *Client) ensureGenesisID() (string, error) {
	genesis, err := c.nc.GetGenesis()
	if err != nil {
		return "", err
	}
	return genesis.ID(), nil
}

// GenesisID fetches the genesis ID for the running algod node
func (c *Client) GenesisID() (string, error) {
	response, err := c.ensureGenesisID()

	if err != nil {
		return "", err
	}
	return response, nil
}

// FullStop stops the clients including graceful shutdown to algod and kmd
func (c *Client) FullStop() error {
	return c.nc.FullStop()
}

func (c *Client) checkHandleValidMaybeRenew(walletHandle []byte) bool {
	// Blank handles are definitely invalid
	if len(walletHandle) == 0 {
		return false
	}
	// Otherwise, check with kmd and possibly renew
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return false
	}
	_, err = kmd.RenewWalletHandle(walletHandle)
	return err == nil
}

// ListAddresses takes a wallet handle and returns the list of addresses associated with it. If no addresses are
// associated with the wallet, it returns an empty list.
func (c *Client) ListAddresses(walletHandle []byte) ([]string, error) {
	las, err := c.ListAddressesWithInfo(walletHandle)
	if err != nil {
		return nil, err
	}

	var addrs []string
	for _, la := range las {
		addrs = append(addrs, la.Addr)
	}

	return addrs, nil
}

// ListAddressesWithInfo takes a wallet handle and returns the list of
// addresses associated with it, along with additional information to
// indicate if an address is multisig or not.  If no addresses are
// associated with the wallet, it returns an empty list.
func (c *Client) ListAddressesWithInfo(walletHandle []byte) ([]ListedAddress, error) {
	// List the keys associated with the walletHandle
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return nil, err
	}
	response, err := kmd.ListKeys(walletHandle)
	if err != nil {
		return nil, err
	}
	// List multisig addresses as well
	response2, err := kmd.ListMultisigAddrs(walletHandle)
	if err != nil {
		return nil, err
	}

	var addresses []ListedAddress
	for _, addr := range response.Addresses {
		addresses = append(addresses, ListedAddress{
			Addr:     addr,
			Multisig: false,
		})
	}

	for _, addr := range response2.Addresses {
		addresses = append(addresses, ListedAddress{
			Addr:     addr,
			Multisig: true,
		})
	}

	return addresses, nil
}

// ListedAddress is an address returned by ListAddresses, with a flag
// to indicate whether it's a multisig address.
type ListedAddress struct {
	Addr     string
	Multisig bool
}

// DeleteAccount deletes an account.
func (c *Client) DeleteAccount(walletHandle []byte, walletPassword []byte, addr string) error {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return err
	}

	_, err = kmd.DeleteKey(walletHandle, walletPassword, addr)
	return err
}

// GenerateAddress takes a wallet handle, generate an additional address for it and returns the public address
func (c *Client) GenerateAddress(walletHandle []byte) (string, error) {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return "", err
	}
	resp, err := kmd.GenerateKey(walletHandle)
	if err != nil {
		return "", err
	}

	return resp.Address, nil
}

// CreateMultisigAccount takes a wallet handle, a list of (nonmultisig) addresses, and a threshold and creates (and returns) a multisig adress
// TODO: Should these be raw public keys instead of addresses so users can't shoot themselves in the foot by passing in a multisig addr? Probably will become irrelevant after CSID changes.
func (c *Client) CreateMultisigAccount(walletHandle []byte, threshold uint8, addrs []string) (string, error) {
	// convert the addresses into public keys
	pks := make([]crypto.PublicKey, len(addrs))
	for i, addrStr := range addrs {
		addr, err := basics.UnmarshalChecksumAddress(addrStr)
		if err != nil {
			return "", err
		}
		pks[i] = crypto.PublicKey(addr)
	}
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return "", err
	}
	resp, err := kmd.ImportMultisigAddr(walletHandle, 1, threshold, pks)
	if err != nil {
		return "", err
	}

	return resp.Address, nil
}

// DeleteMultisigAccount deletes a multisig account.
func (c *Client) DeleteMultisigAccount(walletHandle []byte, walletPassword []byte, addr string) error {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return err
	}

	_, err = kmd.DeleteMultisigAddr(walletHandle, walletPassword, addr)
	return err
}

// LookupMultisigAccount returns the threshold and public keys for a
// multisig address.
func (c *Client) LookupMultisigAccount(walletHandle []byte, multisigAddr string) (info MultisigInfo, err error) {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}

	resp, err := kmd.ExportMultisigAddr(walletHandle, multisigAddr)
	if err != nil {
		return
	}

	var pks []string
	for _, pk := range resp.PKs {
		addr := basics.Address(pk).String()
		pks = append(pks, addr)
	}

	info.Version = resp.Version
	info.Threshold = resp.Threshold
	info.PKs = pks
	return
}

// MultisigInfo represents the information about a multisig account.
type MultisigInfo struct {
	Version   uint8
	Threshold uint8
	PKs       []string
}

// SendPaymentFromWallet signs a transaction using the given wallet and returns the resulted transaction id
func (c *Client) SendPaymentFromWallet(walletHandle, pw []byte, from, to string, fee, amount uint64, note []byte, closeTo string, firstValid, lastValid basics.Round) (transactions.Transaction, error) {
	return c.SendPaymentFromWalletWithLease(walletHandle, pw, from, to, fee, amount, note, closeTo, [32]byte{}, firstValid, lastValid)
}

// SendPaymentFromWalletWithLease is like SendPaymentFromWallet, but with a custom lease.
func (c *Client) SendPaymentFromWalletWithLease(walletHandle, pw []byte, from, to string, fee, amount uint64, note []byte, closeTo string, lease [32]byte, firstValid, lastValid basics.Round) (transactions.Transaction, error) {
	// Build the transaction
	tx, err := c.ConstructPayment(from, to, fee, amount, note, closeTo, lease, firstValid, lastValid)
	if err != nil {
		return transactions.Transaction{}, err
	}

	return c.signAndBroadcastTransactionWithWallet(walletHandle, pw, tx)
}

func (c *Client) signAndBroadcastTransactionWithWallet(walletHandle, pw []byte, tx transactions.Transaction) (transactions.Transaction, error) {
	// Sign the transaction
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return transactions.Transaction{}, err
	}
	// TODO(rekeying) probably libgoal should allow passing in different public key to sign with
	resp0, err := kmd.SignTransaction(walletHandle, pw, crypto.PublicKey{}, tx)
	if err != nil {
		return transactions.Transaction{}, err
	}

	// Decode the SignedTxn
	var stx transactions.SignedTxn
	err = protocol.Decode(resp0.SignedTransaction, &stx)
	if err != nil {
		return transactions.Transaction{}, err
	}

	// Broadcast the transaction
	algod, err := c.ensureAlgodClient()
	if err != nil {
		return transactions.Transaction{}, err
	}

	_, err = algod.SendRawTransaction(stx)
	if err != nil {
		return transactions.Transaction{}, err
	}
	return tx, nil
}

// ComputeValidityRounds takes first, last and rounds provided by a user and resolves them into
// actual firstValid and lastValid.
// Resolution table
//
// validRounds | lastValid | result (lastValid)
// -------------------------------------------------
// 	  	 0     |     0     | firstValid + maxTxnLife
// 		 0     |     N     | lastValid
// 		 M     |     0     | first + validRounds - 1
// 		 M     |     M     | error
//
func (c *Client) ComputeValidityRounds(firstValid, lastValid, validRounds uint64) (uint64, uint64, error) {
	params, err := c.SuggestedParams()
	if err != nil {
		return 0, 0, err
	}
	cparams, ok := c.consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
	if !ok {
		return 0, 0, fmt.Errorf("cannot construct transaction: unknown consensus protocol %s", params.ConsensusVersion)
	}

	return computeValidityRounds(firstValid, lastValid, validRounds, params.LastRound, cparams.MaxTxnLife)
}

func computeValidityRounds(firstValid, lastValid, validRounds, lastRound, maxTxnLife uint64) (uint64, uint64, error) {
	if validRounds != 0 && lastValid != 0 {
		return 0, 0, fmt.Errorf("cannot construct transaction: ambiguous input: lastValid = %d, validRounds = %d", lastValid, validRounds)
	}

	if firstValid == 0 {
		firstValid = lastRound + 1
	}

	if validRounds != 0 {
		// MaxTxnLife is the maximum difference between LastValid and FirstValid
		// so that validRounds = maxTxnLife+1 gives lastValid = firstValid + validRounds - 1 = firstValid + maxTxnLife
		if validRounds > maxTxnLife+1 {
			return 0, 0, fmt.Errorf("cannot construct transaction: txn validity period %d is greater than protocol max txn lifetime %d", validRounds-1, maxTxnLife)
		}
		lastValid = firstValid + validRounds - 1
	} else if lastValid == 0 {
		lastValid = firstValid + maxTxnLife
	}

	if firstValid > lastValid {
		return 0, 0, fmt.Errorf("cannot construct transaction: txn would first be valid on round %d which is after last valid round %d", firstValid, lastValid)
	} else if lastValid-firstValid > maxTxnLife {
		return 0, 0, fmt.Errorf("cannot construct transaction: txn validity period ( %d to %d ) is greater than protocol max txn lifetime %d", firstValid, lastValid, maxTxnLife)
	}

	return firstValid, lastValid, nil
}

// ConstructPayment builds a payment transaction to be signed
// If the fee is 0, the function will use the suggested one form the network
// Although firstValid and lastValid come pre-computed in a normal flow,
// additional validation is done by computeValidityRounds:
// if the lastValid is 0, firstValid + maxTxnLifetime will be used
// if the firstValid is 0, lastRound + 1 will be used
func (c *Client) ConstructPayment(from, to string, fee, amount uint64, note []byte, closeTo string, lease [32]byte, firstValid, lastValid basics.Round) (transactions.Transaction, error) {
	fromAddr, err := basics.UnmarshalChecksumAddress(from)
	if err != nil {
		return transactions.Transaction{}, err
	}

	var toAddr basics.Address
	if to != "" {
		toAddr, err = basics.UnmarshalChecksumAddress(to)
		if err != nil {
			return transactions.Transaction{}, err
		}
	}

	// Get current round, protocol, genesis ID
	params, err := c.SuggestedParams()
	if err != nil {
		return transactions.Transaction{}, err
	}

	cp, ok := c.consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
	if !ok {
		return transactions.Transaction{}, fmt.Errorf("ConstructPayment: unknown consensus protocol %s", params.ConsensusVersion)
	}
	fv, lv, err := computeValidityRounds(uint64(firstValid), uint64(lastValid), 0, params.LastRound, cp.MaxTxnLife)
	if err != nil {
		return transactions.Transaction{}, err
	}

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     fromAddr,
			Fee:        basics.MicroAlgos{Raw: fee},
			FirstValid: basics.Round(fv),
			LastValid:  basics.Round(lv),
			Lease:      lease,
			Note:       note,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: toAddr,
			Amount:   basics.MicroAlgos{Raw: amount},
		},
	}

	// If requesting closing, put it in the transaction.  The protocol might
	// not support it, but in that case, better to fail the transaction,
	// because the user explicitly asked for it, and it's not supported.
	if closeTo != "" {
		closeToAddr, err := basics.UnmarshalChecksumAddress(closeTo)
		if err != nil {
			return transactions.Transaction{}, err
		}

		tx.PaymentTxnFields.CloseRemainderTo = closeToAddr
	}

	tx.Header.GenesisID = params.GenesisID

	// Check if the protocol supports genesis hash
	if cp.SupportGenesisHash {
		copy(tx.Header.GenesisHash[:], params.GenesisHash)
	}

	// Default to the suggested fee, if the caller didn't supply it
	// Fee is tricky, should taken care last. We encode the final transaction to get the size post signing and encoding
	// Then, we multiply it by the suggested fee per byte.
	if fee == 0 {
		tx.Fee = basics.MulAIntSaturate(basics.MicroAlgos{Raw: params.Fee}, tx.EstimateEncodedSize())
	}
	if tx.Fee.Raw < cp.MinTxnFee {
		tx.Fee.Raw = cp.MinTxnFee
	}

	return tx, nil
}

/* Algod Wrappers */

// Status returns the node status
func (c *Client) Status() (resp generatedV2.NodeStatusResponse, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.Status()
	}
	return
}

// AccountInformation takes an address and returns its information
func (c *Client) AccountInformation(account string) (resp v1.Account, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.AccountInformation(account)
	}
	return
}

// AccountInformationV2 takes an address and returns its information
func (c *Client) AccountInformationV2(account string) (resp generatedV2.Account, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.AccountInformationV2(account)
	}
	return
}

// AccountData takes an address and returns its basics.AccountData
func (c *Client) AccountData(account string) (accountData basics.AccountData, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		var resp []byte
		resp, err = algod.RawAccountInformationV2(account)
		if err == nil {
			err = protocol.Decode(resp, &accountData)
		}
	}
	return
}

// AssetInformation takes an asset's index and returns its information
func (c *Client) AssetInformation(index uint64) (resp v1.AssetParams, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.AssetInformation(index)
	}
	return
}

// AssetInformationV2 takes an asset's index and returns its information
func (c *Client) AssetInformationV2(index uint64) (resp generatedV2.Asset, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.AssetInformationV2(index)
	}
	return
}

// ApplicationInformation takes an app's index and returns its information
func (c *Client) ApplicationInformation(index uint64) (resp generatedV2.Application, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.ApplicationInformation(index)
	}
	return
}

// TransactionInformation takes an address and associated txid and return its information
func (c *Client) TransactionInformation(addr, txid string) (resp v1.Transaction, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.TransactionInformation(addr, txid)
	}
	return
}

// PendingTransactionInformation returns information about a recently issued
// transaction based on its txid.
func (c *Client) PendingTransactionInformation(txid string) (resp v1.Transaction, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.PendingTransactionInformation(txid)
	}
	return
}

// Block takes a round and returns its block
func (c *Client) Block(round uint64) (resp v1.Block, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.Block(round)
	}
	return
}

// RawBlock takes a round and returns its block
func (c *Client) RawBlock(round uint64) (resp v1.RawBlock, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.RawBlock(round)
	}
	return
}

// BookkeepingBlock takes a round and returns its block
func (c *Client) BookkeepingBlock(round uint64) (block bookkeeping.Block, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		var resp []byte
		resp, err = algod.RawBlock(round)
		if err == nil {
			var b rpcs.EncodedBlockCert
			err = protocol.DecodeReflect(resp, &b)
			if err != nil {
				return
			}
			block = b.Block
		}
	}
	return
}

// HealthCheck returns an error if something is wrong
func (c *Client) HealthCheck() error {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		err = algod.HealthCheck()
	}
	return err
}

// WaitForRound takes a round, waits until it appears and returns its status. This function blocks.
func (c *Client) WaitForRound(round uint64) (resp generatedV2.NodeStatusResponse, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.StatusAfterBlock(round)
	}
	return
}

// GetBalance takes an address and returns its total balance; if the address doesn't exist, it returns 0.
func (c *Client) GetBalance(address string) (uint64, error) {
	resp, err := c.AccountInformation(address)
	if err != nil {
		return 0, err
	}
	return resp.Amount, nil
}

// AlgodVersions return the list of supported API versions in algod
func (c Client) AlgodVersions() (resp common.Version, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.Versions()
	}
	return
}

// LedgerSupply returns the total number of algos in the system
func (c Client) LedgerSupply() (resp v1.Supply, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.LedgerSupply()
	}
	return
}

// CurrentRound returns the current known round
func (c Client) CurrentRound() (lastRound uint64, err error) {
	// Get current round
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err := algod.Status()
		if err == nil {
			lastRound = resp.LastRound
		}
	}
	return
}

// SuggestedFee returns the suggested fee per byte by the network
func (c *Client) SuggestedFee() (fee uint64, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err := algod.SuggestedFee()
		if err == nil {
			fee = resp.Fee
		}
	}
	return
}

// SuggestedParams returns the suggested parameters for a new transaction
func (c *Client) SuggestedParams() (params v1.TransactionParams, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		params, err = algod.SuggestedParams()
	}
	return
}

// GetPendingTransactions gets a snapshot of current pending transactions on the node.
// If maxTxns = 0, fetches as many transactions as possible.
func (c *Client) GetPendingTransactions(maxTxns uint64) (resp v1.PendingTransactions, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		resp, err = algod.GetPendingTransactions(maxTxns)
	}
	return
}

// ExportKey exports the private key of the passed account, assuming it's available
func (c *Client) ExportKey(walletHandle []byte, password, account string) (resp kmdapi.APIV1POSTKeyExportResponse, err error) {
	kmd, err := c.ensureKmdClient()
	if err != nil {
		return
	}

	// export the secret key for the bidder
	req := kmdapi.APIV1POSTKeyExportRequest{
		WalletHandleToken: string(walletHandle),
		Address:           account,
		WalletPassword:    password,
	}
	resp = kmdapi.APIV1POSTKeyExportResponse{}
	err = kmd.DoV1Request(req, &resp)
	return resp, err
}

// ConsensusParams returns the consensus parameters for the protocol active at the specified round
func (c *Client) ConsensusParams(round uint64) (consensus config.ConsensusParams, err error) {
	block, err := c.Block(round)
	if err != nil {
		return
	}

	params, ok := c.consensus[protocol.ConsensusVersion(block.CurrentProtocol)]
	if !ok {
		err = fmt.Errorf("ConsensusParams: unknown consensus protocol %s", block.CurrentProtocol)
		return
	}

	return params, nil
}

// SetAPIVersionAffinity sets the desired client API version affinity of the algod and kmd clients.
func (c *Client) SetAPIVersionAffinity(algodVersionAffinity algodclient.APIVersion, kmdVersionAffinity kmdclient.APIVersion) {
	c.algodVersionAffinity = algodVersionAffinity
	c.kmdVersionAffinity = kmdVersionAffinity
}

// AbortCatchup aborts the currently running catchup
func (c *Client) AbortCatchup() error {
	algod, err := c.ensureAlgodClient()
	if err != nil {
		return err
	}
	// we need to ensure we're using the v2 status so that we would get the catchpoint information.
	algod.SetAPIVersionAffinity(algodclient.APIVersionV2)
	resp, err := algod.Status()
	if err != nil {
		return err
	}
	if resp.Catchpoint == nil || (*resp.Catchpoint) == "" {
		// no error - we were not catching up.
		return nil
	}
	_, err = algod.AbortCatchup(*resp.Catchpoint)
	if err != nil {
		return err
	}
	return nil
}

// Catchup start catching up to the give catchpoint label.
func (c *Client) Catchup(catchpointLabel string) error {
	algod, err := c.ensureAlgodClient()
	if err != nil {
		return err
	}
	_, err = algod.Catchup(catchpointLabel)
	if err != nil {
		return err
	}
	return nil
}

const defaultAppIdx = 1380011588

// MakeDryrunStateBytes function creates DryrunRequest data structure in serialized form according to the format
func MakeDryrunStateBytes(client Client, txnOrStxn interface{}, other []transactions.SignedTxn, proto string, format string) (result []byte, err error) {
	switch format {
	case "json":
		var gdr generatedV2.DryrunRequest
		gdr, err = MakeDryrunStateGenerated(client, txnOrStxn, other, proto)
		if err == nil {
			result = protocol.EncodeJSON(&gdr)
		}
		return
	case "msgp":
		var dr v2.DryrunRequest
		dr, err = MakeDryrunState(client, txnOrStxn, other, proto)
		if err == nil {
			result = protocol.EncodeReflect(&dr)
		}
		return
	default:
		return nil, fmt.Errorf("format %s not supported", format)
	}
}

// MakeDryrunState function creates v2.DryrunRequest data structure
func MakeDryrunState(client Client, txnOrStxn interface{}, other []transactions.SignedTxn, proto string) (dr v2.DryrunRequest, err error) {
	gdr, err := MakeDryrunStateGenerated(client, txnOrStxn, other, proto)
	if err != nil {
		return
	}
	return v2.DryrunRequestFromGenerated(&gdr)
}

// MakeDryrunStateGenerated function creates generatedV2.DryrunRequest data structure
func MakeDryrunStateGenerated(client Client, txnOrStxn interface{}, other []transactions.SignedTxn, proto string) (dr generatedV2.DryrunRequest, err error) {
	var txns []transactions.SignedTxn
	if txnOrStxn == nil {
		// empty input do nothing
	} else if txn, ok := txnOrStxn.(transactions.Transaction); ok {
		txns = append(txns, transactions.SignedTxn{Txn: txn})
	} else if stxn, ok := txnOrStxn.(transactions.SignedTxn); ok {
		txns = append(txns, stxn)
	} else {
		err = fmt.Errorf("unsupported txn type")
		return
	}

	txns = append(txns, other...)
	for i := range txns {
		enc := protocol.EncodeJSON(&txns[i])
		dr.Txns = append(dr.Txns, enc)
	}

	for _, txn := range txns {
		tx := txn.Txn
		if tx.Type == protocol.ApplicationCallTx {
			apps := []basics.AppIndex{tx.ApplicationID}
			apps = append(apps, tx.ForeignApps...)
			for _, appIdx := range apps {
				var appParams generatedV2.ApplicationParams
				if appIdx == 0 {
					// if it is an app create txn then use params from the txn
					appParams.ApprovalProgram = tx.ApprovalProgram
					appParams.ClearStateProgram = tx.ClearStateProgram
					appParams.GlobalStateSchema = &generatedV2.ApplicationStateSchema{
						NumUint:      tx.GlobalStateSchema.NumUint,
						NumByteSlice: tx.GlobalStateSchema.NumByteSlice,
					}
					appParams.LocalStateSchema = &generatedV2.ApplicationStateSchema{
						NumUint:      tx.LocalStateSchema.NumUint,
						NumByteSlice: tx.LocalStateSchema.NumByteSlice,
					}
					appParams.Creator = tx.Sender.String()
					// zero is not acceptable by ledger in dryrun/debugger
					appIdx = defaultAppIdx
				} else {
					// otherwise need to fetch app state
					var app generatedV2.Application
					if app, err = client.ApplicationInformation(uint64(tx.ApplicationID)); err != nil {
						return
					}
					appParams = app.Params
				}
				dr.Apps = append(dr.Apps, generatedV2.Application{
					Id:     uint64(appIdx),
					Params: appParams,
				})
			}

			accounts := append(tx.Accounts, tx.Sender)
			for _, acc := range accounts {
				var info generatedV2.Account
				if info, err = client.AccountInformationV2(acc.String()); err != nil {
					return
				}
				dr.Accounts = append(dr.Accounts, info)
			}

			dr.ProtocolVersion = proto
			if dr.Round, err = client.CurrentRound(); err != nil {
				return
			}
			var b v1.Block
			if b, err = client.Block(dr.Round); err != nil {
				return
			}
			dr.LatestTimestamp = uint64(b.Timestamp)
		}
	}
	return
}

// Dryrun takes an app's index and returns its information
func (c *Client) Dryrun(data []byte) (resp generatedV2.DryrunResponse, err error) {
	algod, err := c.ensureAlgodClient()
	if err == nil {
		data, err = algod.RawDryrun(data)
		if err != nil {
			return
		}
		err = json.Unmarshal(data, &resp)
	}
	return
}
