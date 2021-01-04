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

package main

import (
	"flag"
	"html/template"
	"net/http"

	"github.com/algorand/websocket"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/commandandcontrol/lib"
)

var addr = flag.String("addr", "localhost:8080", "http service address")

var upgrader = websocket.Upgrader{} // use default options

var clients = make(map[*websocket.Conn]bool)              // map of connected clients
var clientBroadcast = make(chan []byte, 100)              // client broadcast channel
var agents = make(map[*websocket.Conn]bool)               // map of connected agents
var agentBroadcast = make(chan lib.CCServiceRequest, 100) // agent broadcast channel

var log = logging.NewLogger()

func main() {
	flag.Parse()

	http.HandleFunc("/client", handleClientConnections)
	http.HandleFunc("/agent", handleAgentConnections)
	http.HandleFunc("/", webHome)
	go broadcastToAgents()
	go broadcastToClients()
	log.Infof("cc service listening for connections: %s", *addr)
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Errorf("starting http service resulted in error: %v", err)
	}
}

func handleClientConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("upgrade:", err)
		return
	}
	ws.Unsafe = true

	log.Infof("handleClientConnections() with client: %s", ws.RemoteAddr())

	clients[ws] = true

	go monitorClient(ws)
}

func handleAgentConnections(w http.ResponseWriter, r *http.Request) {
	// Upgrade initial GET request to a websocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("problem initializing agent web socket", err)
		return
	}
	ws.Unsafe = true
	log.Infof("handleAgentConnections() new client: %v", ws.RemoteAddr())
	// Register our new client
	agents[ws] = true
	log.Infof("handleAgentConnections client count: %d", len(agents))
	go monitorAgent(ws)
}

func monitorAgent(ws *websocket.Conn) {

	defer func() {
		log.Infof("closing client: %s", ws.RemoteAddr())
		err := ws.Close()
		if err != nil {
			log.Errorf("error closing agent websocket %v", err)
		}
	}()

	for {
		var message []byte
		var messageType int
		messageType, message, err := ws.ReadMessage()
		if err != nil {
			log.Errorf("error: %v", err)
			break
		}
		switch messageType {
		case websocket.TextMessage:
			log.Infof("recieved text from agent: %s", message)
			clientBroadcast <- message
			break
		default:
			log.Infof("recieved other from agent: %s", message)
			break
		}
	}
	// remove the agent from the agent broadcast list
	delete(agents, ws)
}

func monitorClient(ws *websocket.Conn) {

	defer func() {
		log.Infof("closing client: %s", ws.RemoteAddr())
		err := ws.Close()
		if err != nil {
			log.Errorf("error closing agent websocket %v", err)
		}
	}()

	for {
		var managementServiceRequest lib.CCServiceRequest
		err := ws.ReadJSON(&managementServiceRequest)
		if err != nil {
			log.Errorf("error: %v", err)
			break
		}

		log.Infof("recv: %+v", managementServiceRequest)
		for index := range managementServiceRequest.TargetAgentList {
			log.Infof("target agent : %s", managementServiceRequest.TargetAgentList[index])
		}
		sendCommandToAgents(managementServiceRequest)
		err = ws.WriteJSON(managementServiceRequest)
		if err != nil {
			log.Warnf("error sending response to client: %v", err)
			break
		}
	}
	// remove the client from the client broadcast list
	delete(clients, ws)
}

func sendCommandToAgents(managementServiceRequest lib.CCServiceRequest) {
	log.Infof("sendCommandToAgents() sending command %+v", managementServiceRequest)
	log.Infof("sendCommandToAgents() there are %d agents", len(agents))

	agentBroadcast <- managementServiceRequest
}

func broadcastToAgents() {
	log.Infof("broadcastToAgents()\n")
	for {
		// Grab the next message from the agentBroadcast channel
		msg := <-agentBroadcast

		log.Infof("broadcastToAgents: there are %d agents", len(agents))

		// Send it out to every agent that is currently connected
		for agent := range agents {
			log.Infof("broadcastToAgents() sending message %+v", msg)

			err := agent.WriteJSON(msg)
			if err != nil {
				log.Errorf("error: %v", err)
				err = agent.Close()
				if err != nil {
					log.Errorf("error closing agent connection: %v", err)
				}
				delete(agents, agent)
			}
		}
	}
}

func broadcastToClients() {
	log.Infof("broadcastToClients()\n")
	for {
		// Grab the next message from the agentBroadcast channel
		msg := <-clientBroadcast

		log.Infof("broadcastToClients: there are %d clients", len(clients))

		// Send it out to every client that is currently connected
		for client := range clients {
			log.Infof("broadcastToClients() sending message %sn", msg)

			err := client.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				log.Warnf("can't write to client %v", err)
				err = client.Close()
				if err != nil {
					log.Warnf("closing agent connection: %v", err)
				}
				delete(clients, client)
			}
		}
	}
}

func webHome(w http.ResponseWriter, r *http.Request) {
	err := homeTemplate.Execute(w, "ws://"+r.Host+"/client")
	if err != nil {
		log.Errorf("error from web service: %v", err)
	}
}

var homeTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<script>  
window.addEventListener("load", function(evt) {

    var output = document.getElementById("output");
    var component = document.getElementById("component");
    var command = document.getElementById("command");
    var parameters = document.getElementById("parameters");
    var targetList = document.getElementById("targetList");
    var ws;

    var print = function(message) {
        var d = document.createElement("div");
        d.innerHTML = message;
        output.appendChild(d);
    };

    document.getElementById("open").onclick = function(evt) {
        if (ws) {
            return false;
        }
        ws = new WebSocket("{{.}}");
        ws.onopen = function(evt) {
            print("OPEN");
        }
        ws.onclose = function(evt) {
            print("CLOSE");
            ws = null;
        }
        ws.onmessage = function(evt) {
            print("RESPONSE: " + evt.data);
        }
        ws.onerror = function(evt) {
            print("ERROR: " + evt.data);
        }
        return false;
    };

    document.getElementById("send").onclick = function(evt) {
        if (!ws) {
            return false;
        }
        print("SEND: " + command.value);
        tempTargetList = targetList.value.split(",")
		serviceRequest = JSON.stringify({
			'component': component.value,
			'command': command.value,
             'parameters' : parameters.value,
			'targetAgentList': tempTargetList
		});
 		print("sending json: " + serviceRequest);
		ws.send(serviceRequest);
        return false;
    };

    document.getElementById("close").onclick = function(evt) {
        if (!ws) {
            return false;
        }
        ws.close();
        return false;
    };

});
</script>
</head>
<body>
<table>
<tr><td valign="top" width="50%">
<p>Click "Open" to create a connection to the server, 
"Send" to send a message to the server and "Close" to close the connection. 
You can change the message and send multiple times.
<p>
<form>
<button id="open">Open</button>
<button id="close">Close</button>

<p><label>Component:</label>
<input id="component" type="text" value="pingpong">

<p><label>Command:</label>
<input id="command" type="text" value="start">

<p><label>Parameters:</label>
<input id="parameters" type="text" maxlength="100" size="100" value='{"SrcAccount":"","DelayBetweenTxn": 100,"RandomizeFee":false,"RandomizeAmt":false,"RandomizeDst":false,"MaxFee":5,"MaxAmt":20,"NumPartAccounts":10,"RunTime":10000,"RestTime":10000,"RefreshTime":10000,"MinAccountFunds":100000}'>

<p><label>Target List:</label>
<input id="targetList" type="text" value="Host1:Node1, Host1:Primary">

<button id="send">Send</button>
</form>
</td><td valign="top" width="50%">
<div id="output"></div>
</td></tr></table>
</body>
</html>
`))
