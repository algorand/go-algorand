template4xrt:
	sed -e '/\/\* T/ s/^..../\t/' -e '/\/\* G/ s/^/\t\/\/ /' -e 's/Main()/main()/g' experimental.go > experimental.go.tmpl

build-xrt: template4xrt
	go build -o xrt

stateproof-xrt:
	./xrt --repo "github.com/algorand/go-stateproof-verification@x-repo-types" \
		--package "github.com/algorand/go-stateproof-verification/stateproof" \
		--type "StateProof" 

sdk-xrt:
	./xrt --repo "github.com/algorand/go-algorand-sdk/v2@develop" \
		--package "github.com/algorand/go-algorand-sdk/v2/types" \
		--type "LedgerStateDelta" 

goal-xrt:
	./xrt --repo "github.com/algorand/go-algorand" \
		--package "github.com/algorand/go-algorand/ledger/ledgercore" \
		--type "StateDelta"