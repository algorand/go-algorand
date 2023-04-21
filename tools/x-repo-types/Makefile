all: goal-v-sdk goal-v-spv

# go-algorand vs go-algorand-sdk:

goal-v-sdk: goal-v-sdk-state-delta goal-v-sdk-genesis goal-v-sdk-block goal-v-sdk-blockheader goal-v-sdk-stateproof

goal-v-sdk-state-delta:
	./xrt --x-package "github.com/algorand/go-algorand/ledger/ledgercore" \
		--x-type "StateDelta" \
		--y-branch "develop" \
		--y-package "github.com/algorand/go-algorand-sdk/v2/types" \
		--y-type "LedgerStateDelta"

goal-v-sdk-genesis:
	./xrt --x-package "github.com/algorand/go-algorand/data/bookkeeping" \
		--x-type "Genesis" \
		--y-branch "develop" \
		--y-package "github.com/algorand/go-algorand-sdk/v2/types" \
		--y-type "Genesis"

goal-v-sdk-block:
	./xrt --x-package "github.com/algorand/go-algorand/data/bookkeeping" \
		--x-type "Block" \
		--y-branch "develop" \
		--y-package "github.com/algorand/go-algorand-sdk/v2/types" \
		--y-type "Block"

goal-v-sdk-blockheader:
	./xrt --x-package "github.com/algorand/go-algorand/data/bookkeeping" \
		--x-type "BlockHeader" \
		--y-branch "develop" \
		--y-package "github.com/algorand/go-algorand-sdk/v2/types" \
		--y-type "BlockHeader"

goal-v-sdk-stateproof:
	./xrt --x-package "github.com/algorand/go-algorand/crypto/stateproof" \
		--x-type "StateProof" \
		--y-branch "develop" \
		--y-package "github.com/algorand/go-algorand-sdk/v2/types" \
		--y-type "StateProof"

# go-algorand vs go-stateproof-verification:

goal-v-spv: goal-v-spv-stateproof

goal-v-spv-stateproof:
	./xrt --x-package "github.com/algorand/go-algorand/crypto/stateproof" \
		--x-type "StateProof" \
		--y-package "github.com/algorand/go-stateproof-verification/stateproof" \
		--y-type "StateProof"

# reset typeAnalyzer/main.go for passing checks:

reset-dummy-main:
	./xrt --x-package "github.com/algorand/go-algorand/ledger/ledgercore" \
		--x-type "StateDelta" \
		--y-package "github.com/algorand/go-algorand/data/bookkeeping" \
		--y-type "Genesis"
