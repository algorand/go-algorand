all: goal-v-sdk-state-delta-xrt goal-v-sdk-bookkeeping-genesis goal-v-sdk-stateproof goal-v-spv-stateproof

goal-v-sdk-state-delta-xrt:
	./xrt --x-package "github.com/algorand/go-algorand/ledger/ledgercore" \
		--x-type "StateDelta" \
		--y-branch "develop" \
		--y-package "github.com/algorand/go-algorand-sdk/v2/types" \
		--y-type "LedgerStateDelta"

goal-v-sdk-bookkeeping-genesis:
	./xrt --x-package "github.com/algorand/go-algorand/data/bookkeeping" \
		--x-type "Genesis" \
		--y-branch "develop" \
		--y-package "github.com/algorand/go-algorand-sdk/v2/types" \
		--y-type "Genesis"

goal-v-sdk-stateproof:
	./xrt --x-package "github.com/algorand/go-algorand/crypto/stateproof" \
		--x-type "StateProof" \
		--y-branch "develop" \
		--y-package "github.com/algorand/go-algorand-sdk/v2/types" \
		--y-type "StateProof"

goal-v-spv-stateproof:
	./xrt --x-package "github.com/algorand/go-algorand/crypto/stateproof" \
		--x-type "StateProof" \
		--y-package "github.com/algorand/go-stateproof-verification/stateproof" \
		--y-type "StateProof"
