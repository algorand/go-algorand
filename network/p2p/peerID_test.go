// Copyright (C) 2019-2024 Algorand, Inc.
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

package p2p

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestGetPrivKeyUserSupplied(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	tempdir := t.TempDir()
	cfg := config.GetDefaultLocal()
	customPath := path.Join(tempdir, "foobar.pem")
	// generate a new private key
	privKey, err := generatePrivKey()
	require.NoError(t, err)
	// write it to our custom path
	err = writePrivateKeyToFile(customPath, privKey)
	require.NoError(t, err)
	cfg.P2PPrivateKeyLocation = customPath
	// make sure GetPrivKey loads our custom key
	loadedPrivKey, err := GetPrivKey(cfg, tempdir)
	assert.NoError(t, err)
	assert.Equal(t, privKey, loadedPrivKey)
}

func TestGetPrivKeyUserSuppliedDoesNotExistErrors(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	tempdir := t.TempDir()
	cfg := config.GetDefaultLocal()
	cfg.P2PPrivateKeyLocation = path.Join(tempdir, "foobar.pem")
	_, err := GetPrivKey(cfg, tempdir)
	assert.True(t, os.IsNotExist(err))
}

func TestGetPrivKeyDefault(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	tempdir := t.TempDir()
	cfg := config.GetDefaultLocal()

	// generate a new private key
	privKey, err := generatePrivKey()
	require.NoError(t, err)
	// write it to the default path
	err = writePrivateKeyToFile(path.Join(tempdir, DefaultPrivKeyPath), privKey)
	require.NoError(t, err)
	// fetch the default private key
	loadedPrivKey, err := GetPrivKey(cfg, tempdir)
	assert.NoError(t, err)
	assert.Equal(t, privKey, loadedPrivKey)
}

func TestGetPrivKeyUserGeneratedPersisted(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	tempdir := t.TempDir()
	cfg := config.GetDefaultLocal()
	cfg.P2PPersistPeerID = true
	// get a generated private key
	privKey, err := GetPrivKey(cfg, tempdir)
	require.NoError(t, err)
	// make sure it was persisted
	loadedPrivKey, err := loadPrivateKeyFromFile(path.Join(tempdir, DefaultPrivKeyPath))
	assert.NoError(t, err)
	assert.Equal(t, privKey, loadedPrivKey)
}

func TestGetPrivKeyUserGeneratedEphemeral(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	tempdir := t.TempDir()
	cfg := config.GetDefaultLocal()
	cfg.P2PPersistPeerID = false
	// get a generated private key
	_, err := GetPrivKey(cfg, tempdir)
	require.NoError(t, err)
	// make sure it was not persisted
	_, err = loadPrivateKeyFromFile(path.Join(tempdir, DefaultPrivKeyPath))
	assert.True(t, os.IsNotExist(err))
}

func TestPeerIDChallengeSigner(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	privKey, err := generatePrivKey()
	require.NoError(t, err)

	data := make([]byte, 111)
	crypto.RandBytes(data)
	signer := PeerIDChallengeSigner{key: privKey}
	pubKey := privKey.GetPublic()
	pubKeyRaw, err := pubKey.Raw()
	require.NoError(t, err)
	require.Equal(t, crypto.PublicKey(pubKeyRaw), signer.PublicKey())
}
