package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
)

func BenchmarkAlgodStartup(b *testing.B) {
	tmpDir, err := ioutil.TempDir(os.TempDir(), "BenchmarkAlgodStartup")
	require.NoError(b, err)
	defer os.RemoveAll(tmpDir)
	genesisFile, err := ioutil.ReadFile("../../installer/genesis/devnet/genesis.json")
	require.NoError(b, err)

	dataDirectory = &tmpDir
	bInitAndExit := true
	initAndExit = &bInitAndExit
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		err := ioutil.WriteFile(filepath.Join(tmpDir, config.GenesisJSONFile), genesisFile, 0766)
		require.NoError(b, err)
		fmt.Printf("file %s was written\n", filepath.Join(tmpDir, config.GenesisJSONFile))
		run()
		os.RemoveAll(tmpDir)
		os.Mkdir(tmpDir, 0766)
	}
}
