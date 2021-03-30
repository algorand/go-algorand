// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package component

import (
	"fmt"
	"strings"
	"time"

	"github.com/algorand/websocket"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/commandandcontrol/lib"
)

// NewAgent factory method for Agent
func NewAgent() (agent *Agent) {
	var a Agent
	a.componentMap = make(map[string]Component)
	return &a
}

// Agent represents an instance of the CC Agent
type Agent struct {
	Host              Host
	componentMap      map[string]Component
	ServiceConnection *websocket.Conn
	BinDir            string
	TempDir           string
}

// Host represents the server hosting the CC Agent and Algod Nodes
type Host struct {
	Name    string
	NodeMap map[string]AlgodNode
}

// AlgodNode represents an Algod Node (aka Algod Instance)
type AlgodNode struct {
	Name    string
	Status  string
	DataDir string
}

// Common interface that all CC Components must implement
type componentInstanceInterface interface {
	Init() (err error)
	Process(command Command) (err error)
	Terminate() (err error)
}

// Component base structure inherited by all CC Components
type Component struct {
	name                 string
	componentInstanceMap map[string]componentInstanceInterface
}

// Instance represents a Component Instance (component + algod node)
type Instance struct {
	algodName string
	dataDir   string
}

// Init component instance
func (comp *Instance) Init() (err error) {
	return
}

// Process component instance command
func (comp *Instance) Process(command Command) (err error) {
	return
}

// Terminate component instance
func (comp *Instance) Terminate() (err error) {
	return
}

// Command is a command object for Components
type Command struct {
	command string
	options string
	time    int64
	status  CommandStatus
	err     error
}

var hostAgent = NewAgent()

// GetHostAgent returns the Agent singleton for the host
func GetHostAgent() (agent *Agent) {
	return hostAgent
}

// CommandStatus for tracking status of commands
type CommandStatus int

// START, COMPLETED, FAILED are command status values
const (
	START     CommandStatus = 0
	COMPLETED CommandStatus = 1
	FAILED    CommandStatus = 2
)

// PINGPONG name literal
const (
	PINGPONG = "pingpong"
	HOSTINFO = "hostinfo"
)

var log = logging.NewLogger()

// String returns the string value for the command status
func (status CommandStatus) String() string {
	names := [...]string{
		"START",
		"COMPLETED",
		"FAILED"}
	if status < START || status > FAILED {
		return "Unknown"
	}
	return names[status]
}

// ProcessRequest processes the command received via the CC Service
func (agent *Agent) ProcessRequest(managementServiceRequest lib.CCServiceRequest) (err error) {
	log.Infof("received command for %s\n", managementServiceRequest.Component)
	err = agent.ServiceConnection.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("received request %+v ", managementServiceRequest)))
	if err != nil {
		log.Errorf("problem sending ack to client , %v", err)
	}
	switch managementServiceRequest.Component {
	case PINGPONG:
		agent.processPingPongComponentRequest(managementServiceRequest)
	case HOSTINFO:
		log.Warnf("not implemented\n")
	default:
		log.Errorf("usupported component type: %s", managementServiceRequest.Component)
	}
	return
}

// Return the node list for the target agent list
func (agent *Agent) getTargetNodeList(targetAgentList []string) (nodeList []string) {
	// determine the list of targeted nodes
	for _, target := range targetAgentList {
		target := strings.TrimSpace(target)
		targetParts := strings.Split(target, ":")
		targetHost := targetParts[0]
		if targetHost == "*" || targetHost == agent.Host.Name {
			targetNode := targetParts[1]
			for _, node := range agent.Host.NodeMap {
				if targetNode == "*" || targetNode == node.Name {
					nodeList = append(nodeList, node.Name)
				}
			}
		}
	}
	return
}

// lookup the component by name
func (agent *Agent) lookupComponentByName(componentName string) (component Component) {
	var ok bool
	if component, ok = agent.componentMap[componentName]; !ok {
		component = Component{
			name:                 componentName,
			componentInstanceMap: make(map[string]componentInstanceInterface),
		}
		agent.componentMap[componentName] = component
	}
	return
}

// create a new component command based on the service request
func (agent *Agent) makeNewComponentCommand(managementServiceRequest lib.CCServiceRequest) (componentCommand Command) {
	// create a new command object from the request
	componentCommand = Command{
		command: managementServiceRequest.Command,
		options: managementServiceRequest.Parameters,
		time:    time.Now().Unix(),
		status:  START,
	}
	return
}

func (agent *Agent) processPingPongComponentRequest(managementServiceRequest lib.CCServiceRequest) {

	var ok bool
	var componentInstance componentInstanceInterface

	componentCommand := agent.makeNewComponentCommand(managementServiceRequest)

	// get the PingPong Component
	component := agent.lookupComponentByName(PINGPONG)

	// get the target list of matching nodes
	nodeList := agent.getTargetNodeList(managementServiceRequest.TargetAgentList)

	// send the command to each of the matching nodes
	for _, node := range nodeList {
		// dispatch command to targeted agent node instances
		if componentInstance, ok = component.componentInstanceMap[node]; !ok {
			componentInstance = &PingPongComponentInstance{ctx: nil, cancelFunc: nil, ci: Instance{algodName: node, dataDir: agent.Host.NodeMap[node].DataDir}}
			err := componentInstance.Init()
			if err != nil {
				log.Errorf("error processing ping pong component request %v", err)
			} else {
				component.componentInstanceMap[node] = componentInstance
			}
		}
		err := componentInstance.Process(componentCommand)
		if err != nil {
			log.Errorf("error processing ping pong component request %v", err)
			err = agent.ServiceConnection.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("error processing request %+v with err: %v", managementServiceRequest, err)))
			if err != nil {
				log.Errorf("error sending message to service %v", err)
			}

		} else {
			componentCommand.status = COMPLETED
		}
	}
}
