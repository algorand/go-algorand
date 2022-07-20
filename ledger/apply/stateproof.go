package apply

import (
	"fmt"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// StateProof applies the StateProof transaction and by setting the next StateProof round
func StateProof(tx transactions.StateProofTxnFields, atRound basics.Round, cs StateProofData, validate bool) error {
	latestRoundInInterval := tx.StateProofIntervalLatestRound
	spType := tx.StateProofType
	stateProof := tx.StateProof
	stateProofMsg := tx.Message

	if spType != protocol.StateProofBasic {
		return fmt.Errorf("applyStateProof type %d not supported", spType)
	}

	nextStateProofRnd := cs.StateProofNext()

	latestRoundHdr, err := cs.BlockHdr(latestRoundInInterval)
	if err != nil {
		return err
	}

	proto := config.Consensus[latestRoundHdr.CurrentProtocol]

	if validate {
		votersRnd := latestRoundInInterval.SubSaturate(basics.Round(proto.StateProofInterval))
		votersHdr, err := cs.BlockHdr(votersRnd)
		if err != nil {
			return err
		}

		err = cs.ValidateStateProof(latestRoundHdr, stateProof, votersHdr, nextStateProofRnd, atRound, stateProofMsg)
		if err != nil {
			return err
		}
	}

	cs.SetStateProofNext(latestRoundInInterval + basics.Round(proto.StateProofInterval))
	return nil
}
