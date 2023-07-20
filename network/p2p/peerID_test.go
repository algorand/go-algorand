package p2p

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
)

func TestGetPrivKeyUserSupplied(t *testing.T) {
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
	tempdir := t.TempDir()
	cfg := config.GetDefaultLocal()
	cfg.P2PPrivateKeyLocation = path.Join(tempdir, "foobar.pem")
	_, err := GetPrivKey(cfg, tempdir)
	assert.True(t, os.IsNotExist(err))
}

func TestGetPrivKeyDefault(t *testing.T) {
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
	tempdir := t.TempDir()
	cfg := config.GetDefaultLocal()
	// get a generated private key
	privKey, err := GetPrivKey(cfg, tempdir)
	require.NoError(t, err)
	// make sure it was persisted
	loadedPrivKey, err := loadPrivateKeyFromFile(path.Join(tempdir, DefaultPrivKeyPath))
	assert.NoError(t, err)
	assert.Equal(t, privKey, loadedPrivKey)
}

func TestGetPrivKeyUserGeneratedEphemeral(t *testing.T) {
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
