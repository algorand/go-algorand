package testing

import (
	"reflect"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/test/reflectionhelpers"
	"github.com/stretchr/testify/assert"
)

func TestAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	accountDataType := reflect.TypeOf(basics.AccountData{})

	referencedAccountTypes := make([]reflectionhelpers.TypePath, 0)
	reflectionhelpers.IterateReferencedTypes(accountDataType, func(path reflectionhelpers.TypePath, stack []reflect.Type) bool {
		if len(path) == 0 {
			return true
		}
		if path[len(path)-1].FieldName == "_struct" && stack[len(stack)-1] == reflect.TypeOf(struct{}{}) {
			return true
		}
		referencedAccountTypes = append(referencedAccountTypes, path.Clone())
		return true
	})

	// If this test becomes flaky, increase niter
	niter := 1000

	accountFieldSeenZero := make([]bool, len(referencedAccountTypes))
	accountFieldSeenNonzero := make([]bool, len(referencedAccountTypes))

	accounts := RandomAccounts(niter, false)
	for _, account := range accounts {
		accountValue := reflect.ValueOf(account)
		for i, typePath := range referencedAccountTypes {
			values := typePath.ResolveValues(accountValue)

			for _, value := range values {
				isZero := value.IsZero()
				if value.Kind() == reflect.Slice || value.Kind() == reflect.Map {
					fieldLen := value.Len()
					isZero = fieldLen == 0
				}
				if !accountFieldSeenZero[i] && isZero {
					accountFieldSeenZero[i] = true
				}
				if !accountFieldSeenNonzero[i] && !isZero {
					accountFieldSeenNonzero[i] = true
				}
			}
		}
	}

	// It's ok for these fields to never be the zero value
	zeroValueExceptions := []reflectionhelpers.TypePath{
		reflectionhelpers.TypePath{}.AddField("MicroAlgos"),
		reflectionhelpers.TypePath{}.AddField("MicroAlgos").AddField("Raw"),
		reflectionhelpers.TypePath{}.AddField("AssetParams").AddMapKey(),
		reflectionhelpers.TypePath{}.AddField("AssetParams").AddValue(),
		reflectionhelpers.TypePath{}.AddField("AssetParams").AddValue().AddField("Total"),
		reflectionhelpers.TypePath{}.AddField("Assets").AddMapKey(),
		reflectionhelpers.TypePath{}.AddField("Assets").AddValue(),
		reflectionhelpers.TypePath{}.AddField("AppLocalStates").AddMapKey(),
		reflectionhelpers.TypePath{}.AddField("AppLocalStates").AddValue(),
		reflectionhelpers.TypePath{}.AddField("AppLocalStates").AddValue().AddField("KeyValue").AddValue(),
		reflectionhelpers.TypePath{}.AddField("AppLocalStates").AddValue().AddField("KeyValue").AddValue().AddField("Type"),
		reflectionhelpers.TypePath{}.AddField("AppParams").AddMapKey(),
		reflectionhelpers.TypePath{}.AddField("AppParams").AddValue(),
		reflectionhelpers.TypePath{}.AddField("AppParams").AddValue().AddField("ApprovalProgram"),
		reflectionhelpers.TypePath{}.AddField("AppParams").AddValue().AddField("ClearStateProgram"),
		reflectionhelpers.TypePath{}.AddField("AppParams").AddValue().AddField("GlobalState").AddValue(),
		reflectionhelpers.TypePath{}.AddField("AppParams").AddValue().AddField("GlobalState").AddValue().AddField("Type"),
	}

	for _, exception := range zeroValueExceptions {
		// ensure all exceptions can resolve without panicking
		exception.ResolveType(accountDataType)
	}

	// It's ok for these fields to always be the zero value
	nonzeroValueExceptions := []reflectionhelpers.TypePath{
		reflectionhelpers.TypePath{}.AddField("RewardsBase"),
		// It would be great to have these fields NOT always be zero, but ledger/accountdb_test.go
		// currently depends on this.
		reflectionhelpers.TypePath{}.AddField("RewardedMicroAlgos"),
		reflectionhelpers.TypePath{}.AddField("RewardedMicroAlgos").AddField("Raw"),
	}

	for _, exception := range nonzeroValueExceptions {
		// ensure all exceptions can resolve without panicking
		exception.ResolveType(accountDataType)
	}

	for i, typePath := range referencedAccountTypes {
		skipZeroValueCheck := false
		for _, exception := range zeroValueExceptions {
			if exception.Equals(typePath) {
				skipZeroValueCheck = true
				break
			}
		}

		skipNonZeroValueCheck := false
		for _, exception := range nonzeroValueExceptions {
			if exception.Equals(typePath) {
				skipNonZeroValueCheck = true
				break
			}
		}

		referencedType := typePath.ResolveType(accountDataType)

		if !skipZeroValueCheck {
			assert.Truef(t, accountFieldSeenZero[i], "Path '%s' (type %v) was never seen with a zero value", typePath, referencedType)
		}
		if !skipNonZeroValueCheck {
			assert.Truef(t, accountFieldSeenNonzero[i], "Path '%s' (type %v) was always seen with a zero value", typePath, referencedType)
		}
	}
}
