package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/net/websocket"

	"github.com/algorand/go-algorand/data/transactions/logic"
)

type ExecID string

type debugConfig struct {
	// If -1, don't break
	BreakOnPC int `json:"breakonpc"`
}

type execContext struct {
	// Reply to registration/update when bool received on acknolwedgement
	// channel, allowing program execution to continue
	acknowledged chan bool

	// debugConfigs holds information about this debugging session,
	// currently just when we want to break
	debugConfig debugConfig
}

type ConfigRequest struct {
	debugConfig
	ExecID ExecID `json:"execid"`
}

type ContinueRequest struct {
	ExecID ExecID `json:"execid"`
}

type Notification struct {
	Event         string              `json:"event"`
	DebuggerState logic.DebuggerState `json:"state"`
}

type requestContext struct {
	// Prevent races when accessing maps
	mux sync.Mutex

	// Receive registration, update, and completed notifications from TEAL
	notifications chan Notification

	// Last subscription ID used for notifications broadcasts to web clients
	maxSubID uint64

	// Broadcast notifications to all web clients over their respective channels
	subscriptions map[uint64]chan Notification

	// State stored per execution
	execContexts map[ExecID]execContext
}

func (rctx *requestContext) register(state logic.DebuggerState) {
	var exec execContext

	// Allocate a default debugConfig (don't break)
	exec.debugConfig = debugConfig{
		BreakOnPC: -1,
	}

	// Allocate an acknowledgement channel
	exec.acknowledged = make(chan bool)

	// Store the state for this execution
	rctx.mux.Lock()
	rctx.execContexts[ExecID(state.ExecID)] = exec
	rctx.mux.Unlock()

	// Inform the user to configure execution
	rctx.notifications <- Notification{"registered", state}

	// Wait for acknowledgement
	<-exec.acknowledged
}

func (rctx *requestContext) registerHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a logic.DebuggerState from the request
	var state logic.DebuggerState
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&state)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Register, and wait for user to acknowledge registration
	rctx.register(state)

	// Proceed!
	w.WriteHeader(http.StatusBadRequest)
	return
}

func (rctx *requestContext) updateHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a logic.DebuggerState from the request
	var state logic.DebuggerState
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&state)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Grab execution context
	exec, ok := rctx.fetchExecContext(ExecID(state.ExecID))
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	go func() {
		// Check if we are triggered and acknolwedge asynchronously
		cfg := exec.debugConfig
		if cfg.BreakOnPC != -1 {
			if state.PC >= cfg.BreakOnPC {
				// Breakpoint hit! Inform the user
				rctx.notifications <- Notification{"updated", state}
			} else {
				// Continue if we haven't hit the next breakpoint 
				exec.acknowledged <- true
			}
		} else {
			// User won't send acknowledement, so we will
			exec.acknowledged <- true
		}
	}()

	// Let TEAL continue when acknowledged
	<-exec.acknowledged
	w.WriteHeader(http.StatusOK)
	return
}

func (rctx *requestContext) fetchExecContext(eid ExecID) (execContext, bool) {
	rctx.mux.Lock()
	defer rctx.mux.Unlock()
	exec, ok := rctx.execContexts[eid]
	return exec, ok
}

func (rctx *requestContext) completeHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a logic.DebuggerState from the request
	var state logic.DebuggerState
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&state)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Inform the user
	rctx.notifications <- Notification{"completed", state}

	// Clean up exec-specific state
	rctx.mux.Lock()
	delete(rctx.execContexts, ExecID(state.ExecID))
	rctx.mux.Unlock()

	// Proceed!
	w.WriteHeader(http.StatusOK)
	return
}

func (rctx *requestContext) configHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a ConfigRequest
	var req ConfigRequest
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Ensure that we are trying to configure an execution we know about
	exec, ok := rctx.fetchExecContext(req.ExecID)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Update the config
	exec.debugConfig = req.debugConfig

	// Write the config
	rctx.mux.Lock()
	rctx.execContexts[ExecID(req.ExecID)] = exec
	rctx.mux.Unlock()

	w.WriteHeader(http.StatusOK)
	return
}

func (rctx *requestContext) continueHandler(w http.ResponseWriter, r *http.Request) {
	// Decode a ContinueRequest
	var req ContinueRequest
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Ensure that we are trying to continue an execution we know about
	exec, ok := rctx.fetchExecContext(req.ExecID)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Try to continue
	select {
	case exec.acknowledged <- true:
	default:
	}

	w.WriteHeader(http.StatusOK)
	return
}

func (rctx *requestContext) homeHandler(w http.ResponseWriter, r *http.Request) {
	home, err := template.ParseFiles("/home/maxj/Projects/algorand/go-algorand/cmd/tealdbg/home.html")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	home.Execute(w, nil)
	return
}

func (rctx *requestContext) broadcastNotifications() {
	for {
		select {
		case notification := <-rctx.notifications:
			rctx.mux.Lock()
			for _, ch := range rctx.subscriptions {
				select {
					case ch <- notification:
					default:
				}
			}
			rctx.mux.Unlock()
		}
	}
}

func (rctx *requestContext) registerNotifications() (uint64, chan Notification) {
	rctx.mux.Lock()
	defer rctx.mux.Unlock()
	rctx.maxSubID++
	notifications := make(chan Notification)
	rctx.subscriptions[rctx.maxSubID] = notifications
	return rctx.maxSubID, notifications
}

func (rctx *requestContext) unregisterNotifications(id uint64) {
	rctx.mux.Lock()
	defer rctx.mux.Unlock()
	delete(rctx.subscriptions, id)
}

func (rctx *requestContext) subscribeHandler(ws *websocket.Conn) {
	defer ws.Close()

	// Acknowledge connection
	event := Notification{
		Event: "connected",
	}
	enc, err := json.Marshal(event)
	if err != nil {
		return
	}
	err = websocket.Message.Send(ws, string(enc))
	if err != nil {
		return
	}

	subid, notifications := rctx.registerNotifications()
	defer rctx.unregisterNotifications(subid)

	// Wait on notifications and forward to the user
	for {
		select {
		case notification := <-notifications:
			enc, err := json.Marshal(notification)
			if err != nil {
				return
			}
			err = websocket.Message.Send(ws, string(enc))
			if err != nil {
				return
			}
		}
	}
}

func main() {
	router := mux.NewRouter()

	appAddress := "localhost:9392"

	rctx := requestContext{
		mux:           sync.Mutex{},
		notifications: make(chan Notification),
		subscriptions: make(map[uint64]chan Notification),
		execContexts:  make(map[ExecID]execContext),
	}

	// Requests from TEAL evaluator
	router.HandleFunc("/exec/register", rctx.registerHandler).Methods("POST")
	router.HandleFunc("/exec/update", rctx.updateHandler).Methods("POST")
	router.HandleFunc("/exec/complete", rctx.completeHandler).Methods("POST")

	// Requests from client
	router.HandleFunc("/", rctx.homeHandler).Methods("GET")
	router.HandleFunc("/exec/config", rctx.configHandler).Methods("POST")
	router.HandleFunc("/exec/continue", rctx.continueHandler).Methods("POST")

	// Websocket requests from client
	ws := websocket.Server{
		Handler: rctx.subscribeHandler,
	}
	router.Handle("/ws", ws)

	server := http.Server{
		Handler:      router,
		Addr:         appAddress,
		WriteTimeout: time.Duration(0),
		ReadTimeout:  time.Duration(0),
	}

	go rctx.broadcastNotifications()

	log.Printf("starting server on %s", appAddress)
	server.ListenAndServe()
}
