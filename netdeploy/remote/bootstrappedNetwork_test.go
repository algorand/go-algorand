package remote

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadBootstrappedData(t *testing.T) {
	badSpecPath := filepath.Join("./../../test", "testdata/deployednettemplates/networks/bootstrapped/badSpec.json")
	_, err := LoadBootstrappedData(badSpecPath)
	require.NotEqual(t, nil, err)

	okSpecPath := filepath.Join("./../../test", "testdata/deployednettemplates/networks/bootstrapped/okSpec.json")
	var data BootstrappedNetwork
	data, err = LoadBootstrappedData(okSpecPath)
	expected := BootstrappedNetwork{
		NumRounds:                 65000,
		RoundTransactionsCount:    1000,
		GeneratedAccountsCount:    7000000,
		GeneratedAssetsCount:      200000,
		GeneratedApplicationCount: 1000000,
		SourceWalletName:          "wallet1",
	}
	require.Equal(t, nil, err)
	require.Equal(t, data.NumRounds, expected.NumRounds)
	require.Equal(t, data.RoundTransactionsCount, expected.RoundTransactionsCount)
	require.Equal(t, data.GeneratedAccountsCount, expected.GeneratedAccountsCount)
	require.Equal(t, data.GeneratedAssetsCount, expected.GeneratedAssetsCount)
	require.Equal(t, data.GeneratedApplicationCount, expected.GeneratedApplicationCount)
	require.Equal(t, data.SourceWalletName, expected.SourceWalletName)
}
