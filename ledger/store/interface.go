package store

import "github.com/algorand/go-algorand/data/basics"

// AccountsWriter is the write interface for:
// - accounts, resources, app kvs, creatables
type AccountsWriter interface {
	InsertAccount(addr basics.Address, normBalance uint64, data BaseAccountData) (rowid int64, err error)
	DeleteAccount(rowid int64) (rowsAffected int64, err error)
	UpdateAccount(rowid int64, normBalance uint64, data BaseAccountData) (rowsAffected int64, err error)

	InsertResource(addrid int64, aidx basics.CreatableIndex, data ResourcesData) (rowid int64, err error)
	DeleteResource(addrid int64, aidx basics.CreatableIndex) (rowsAffected int64, err error)
	UpdateResource(addrid int64, aidx basics.CreatableIndex, data ResourcesData) (rowsAffected int64, err error)

	UpsertKvPair(key string, value []byte) error
	DeleteKvPair(key string) error

	InsertCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType, creator []byte) (rowid int64, err error)
	DeleteCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType) (rowsAffected int64, err error)

	Close()
}

// AccountsReader is the read interface for:
// - accounts, resources, app kvs, creatables
type AccountsReader interface {
	ListCreatables(maxIdx basics.CreatableIndex, maxResults uint64, ctype basics.CreatableType) (results []basics.CreatableLocator, dbRound basics.Round, err error)

	Lookup(addr basics.Address) (data PersistedAccountData, err error)

	LookupResources(addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (data PersistedResourcesData, err error)
	LookupAllResources(addr basics.Address) (data []PersistedResourcesData, rnd basics.Round, err error)

	LookupKeyValue(key string) (pv PersistedKVData, err error)
	LookupKeysByPrefix(prefix string, maxKeyNum uint64, results map[string]bool, resultCount uint64) (round basics.Round, err error)

	LookupCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (addr basics.Address, ok bool, dbRound basics.Round, err error)

	Close()
}

// OnlineAccountsWriter is the write interface for:
// - online accounts
type OnlineAccountsWriter interface {
	InsertOnlineAccount(addr basics.Address, normBalance uint64, data BaseOnlineAccountData, updRound uint64, voteLastValid uint64) (rowid int64, err error)

	Close()
}

// OnlineAccountsReader is the read interface for:
// - online accounts
type OnlineAccountsReader interface {
	LookupOnline(addr basics.Address, rnd basics.Round) (data PersistedOnlineAccountData, err error)
	LookupOnlineTotalsHistory(round basics.Round) (basics.MicroAlgos, error)
	LookupOnlineHistory(addr basics.Address) (result []PersistedOnlineAccountData, rnd basics.Round, err error)

	Close()
}
