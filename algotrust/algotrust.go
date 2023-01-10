package algotrust

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
)

const coolDown = time.Duration(200 * time.Millisecond)

type score struct {
	points      uint64
	lastAttempt atomic.Value
}

type AlgoTrust struct {
	mu          sync.RWMutex
	txnMapMu    sync.RWMutex
	nbw         *newBlockWatcher
	scoreBoard  map[string]*score
	txnToSender map[[8]byte][]string
}

type LedgerForBlockNotification interface {
	RegisterBlockListeners([]ledgercore.BlockListener)
}

type getSenderPeer interface {
	GetAddress() string
}

func MakeAlgoTrust(ledger LedgerForBlockNotification) *AlgoTrust {
	nbw := makenewBlockWatcher()
	ledger.RegisterBlockListeners([]ledgercore.BlockListener{nbw})
	at := &AlgoTrust{
		nbw:         nbw,
		scoreBoard:  make(map[string]*score),
		txnToSender: make(map[[8]byte][]string),
	}
	nbw.at = at
	return at
}

func getFirstSigEightBytes(stxn *transactions.SignedTxn) (sig [8]byte, err error) {
	if stxn.Sig != (crypto.Signature{}) {
		copy(sig[:], stxn.Sig[:8])
		return
	}
	if !stxn.Msig.Blank() {
		copy(sig[:], stxn.Msig.Subsigs[0].Sig[:8])
		return
	}
	return sig, errors.New("unsupported sig type")
}

func (at *AlgoTrust) updateCounters(block *bookkeeping.Block) {
	at.mu.RLock()
	defer at.mu.RUnlock()
	for t := range block.Payset {
		sig, err := getFirstSigEightBytes(&block.Payset[t].SignedTxnWithAD.SignedTxn)
		if err != nil {
			// Lsig is not supported yet
			continue
		}
		at.txnMapMu.Lock()
		senders := at.txnToSender[sig]
		// delete the list, and give them the credit
		// if someone else sends the same transaction after this, will not get credit, rightfully, since it is too late
		delete(at.txnToSender, sig)
		at.txnMapMu.Unlock()
		for s := range senders {
			sc, has := at.scoreBoard[senders[s]]
			if !has {
				at.mu.RUnlock()
				at.mu.Lock()
				at.scoreBoard[senders[s]] = &score{points: 2} // lastAttempt is not relevant anymore
				at.mu.Unlock()
				at.mu.RLock()
				continue
			}
			atomic.AddUint64(&sc.points, uint64(2))
		}
	}
}

// newBlockWatcher is a struct used to provide a new block header to the
// stream verifier
type newBlockWatcher struct {
	blk atomic.Value
	at  *AlgoTrust
}

// makenewBlockWatcher construct a new block watcher with the initial blkHdr
func makenewBlockWatcher() (nbw *newBlockWatcher) {
	nbw = &newBlockWatcher{}
	return nbw
}

// OnNewBlock implements the interface to subscribe to new block notifications from the ledger
func (nbw *newBlockWatcher) OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta) {
	nbw.blk.Store(&block)
	go func() {
		blk := nbw.blk.Load().(*bookkeeping.Block)
		nbw.at.updateCounters(blk)
	}()

}

// PreprocessTxnFiltering returns shouldDrop: true with outMsg if the txn should not be accepted, and shouldDrop: false if the txn should be accepted
// internally, it performs two tasks:
//  1. Subtracts 1 point if available, otherwise, rejects if last attempt was soon enough, else allows it in and records the time
//  2. records the transaction and associates it with the sender
func (at *AlgoTrust) PreprocessTxnFiltering(rawmsg network.IncomingMessage) (shouldDrop bool, outMsg network.OutgoingMessage) {
	addr, err := getSender(rawmsg.Sender)
	if err != nil {
		logging.Base().Infof("PreprocessTxnFiltering: %v %v", rawmsg.Sender, err)
		return false, network.OutgoingMessage{}
	}
	at.mu.RLock()
	sc, has := at.scoreBoard[addr]
	if has {
		defer at.mu.RUnlock()
	} else {
		// this is a new sender
		// upgrade the lock since will be making a write to the map
		at.mu.RUnlock()
		now := time.Now()
		sc := score{points: 0}
		at.mu.Lock()
		at.scoreBoard[addr] = &sc
		sc.lastAttempt.Store(&now)
		at.mu.Unlock()
		return false, network.OutgoingMessage{}
	}

	// here, allowing two situations to avoid obtaining a write lock:
	// 1. take a chance with race condition. If the scoreboard for this address is updated by updateCounters, the update is atomic, but,
	//    will trigger race condition if the exact same address is updated at the same time. It does not matter, because, the points will
	//    not be lost and can be used later.
	// 2. if the same address is having more than one txn sent at the same time here, and in all goroutines, the same number of points will be
	//    read, and all the goroutines will write the initially read points - 1, hence, all the simultaneously submitted transactions will get
	//    in with 1 point deduction. Since this is rare, and the number of goroutines is bounded, this is acceptable.
	if sc.points == 0 {
		// has no points for a new transaction. check when was the last attempt, and if more than cooldown, let it go
		lastAttempt := sc.lastAttempt.Load().(*time.Time)
		if time.Since(*lastAttempt) > coolDown {
			now := time.Now()
			sc.lastAttempt.Store(&now)
			return false, network.OutgoingMessage{}
		} else {
			// has no points, and last attempt was less than the coolDown
			return true, network.OutgoingMessage{Action: network.Disconnect}
		}
	} else {
		// use the points and let it in. here, use store instead of add a negative value, to avoid going negative in case multiple goroutines
		// are updating the same value
		oldValue := sc.points
		if oldValue > 0 {
			atomic.StoreUint64(&sc.points, oldValue-1)
		}
		return false, network.OutgoingMessage{}
	}
}

// RecordTxnsaction will add the sender's address to the txn map
// TODO: maybe release the lock here?
func (at *AlgoTrust) RecordTxnsaction(stxn *transactions.SignedTxn, sender network.Peer) {
	addr, err := getSender(sender)
	if err != nil {
		logging.Base().Infof("RecordTxnsaction: %v %v", sender, err)
		return
	}
	sig, err := getFirstSigEightBytes(stxn)
	if err != nil {
		// TODO: handle this case
		return
	}
	at.txnMapMu.RLock()
	defer at.txnMapMu.RUnlock()
	senders, has := at.txnToSender[sig]
	if has {
		at.txnToSender[sig] = append(senders, addr)
	} else {
		senders = make([]string, 1)
		senders[0] = addr
		at.txnToSender[sig] = senders
	}
}

func getSender(sender network.Peer) (addr string, err error) {
	if sender == nil {
		return addr, errors.New("peer not supported for obtaining the address")
	}
	s, ok := sender.(getSenderPeer)
	if !ok {
		// this is unsupported (TODO)
		return addr, errors.New("peer not supported for obtaining the address")
	}

	addr = s.GetAddress()
	return

}
