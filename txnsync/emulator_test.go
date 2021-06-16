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

package txnsync

import (
	"fmt"
	"testing"
	"time"

	"github.com/algorand/go-algorand/data/basics"
)

type connectionSettings struct {
	uploadSpeed   uint64 // measured in bytes/second
	downloadSpeed uint64 // measured in bytes/second
	target        int    // node index in the networkConfiguration
}

type nodeConfiguration struct {
	outgoingConnections []connectionSettings
	name                string
	isRelay             bool
}

// networkConfiguration defines the nodes setup and their connections.
type networkConfiguration struct {
	nodes []nodeConfiguration
}

// initialTransactionsAllocation defines how many transaction ( and what their sizes ) would be.
type initialTransactionsAllocation struct {
	node              int // node index in the networkConfiguration
	transactionsCount int
	transactionSize   int
	expirationRound   basics.Round
}

// scenario defines the emulator test scenario, which includes the network configuration,
// initial transaction distribution, test duration, dynamic transactions creation as well
// as expected test outcomes.
type scenario struct {
	netConfig       networkConfiguration
	testDuration    time.Duration
	step            time.Duration
	initialAlloc    []initialTransactionsAllocation
	expectedResults emulatorResult
}

func TestEmulatedTrivialTransactionsExchange(t *testing.T) {
	testScenario := scenario{
		netConfig: networkConfiguration{
			nodes: []nodeConfiguration{
				{
					name:    "relay",
					isRelay: true,
				},
				{
					name: "node",
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
					},
				},
			},
		},
		testDuration: 500 * time.Millisecond,
		initialAlloc: []initialTransactionsAllocation{
			initialTransactionsAllocation{
				node:              1,
				transactionsCount: 1,
				transactionSize:   250,
				expirationRound:   basics.Round(5),
			},
		},
		expectedResults: emulatorResult{
			nodes: []nodeTransactions{
				{
					nodeTransaction{
						expirationRound: 5,
						transactionSize: 250,
					},
				},
				{
					nodeTransaction{
						expirationRound: 5,
						transactionSize: 250,
					},
				},
			},
		},
		step: 1 * time.Millisecond,
	}
	t.Run("NonRelay_To_Relay", func(t *testing.T) {
		testScenario.netConfig.nodes[0].name = "relay"
		testScenario.netConfig.nodes[0].isRelay = true
		testScenario.netConfig.nodes[1].name = "node"
		testScenario.initialAlloc[0].node = 1
		emulateScenario(t, testScenario)
	})
	t.Run("Relay_To_NonRelay", func(t *testing.T) {
		testScenario.netConfig.nodes[0].name = "relay"
		testScenario.netConfig.nodes[0].isRelay = true
		testScenario.netConfig.nodes[1].name = "node"
		testScenario.initialAlloc[0].node = 0
		emulateScenario(t, testScenario)
	})
	t.Run("OutgoingRelay_To_IncomingRelay", func(t *testing.T) {
		testScenario.netConfig.nodes[0].name = "incoming-relay"
		testScenario.netConfig.nodes[0].isRelay = true
		testScenario.netConfig.nodes[1].name = "outgoing-relay"
		testScenario.netConfig.nodes[1].isRelay = true
		testScenario.initialAlloc[0].node = 1
		emulateScenario(t, testScenario)
	})
	t.Run("IncomingRelay_To_OutgoingRelay", func(t *testing.T) {
		testScenario.netConfig.nodes[0].name = "incoming-relay"
		testScenario.netConfig.nodes[0].isRelay = true
		testScenario.netConfig.nodes[1].name = "outgoing-relay"
		testScenario.netConfig.nodes[1].isRelay = true
		testScenario.initialAlloc[0].node = 0
		emulateScenario(t, testScenario)
	})
}

func TestEmulatedTwoNodesToRelaysTransactionsExchange(t *testing.T) {
	// this test creates the following network mode:
	//
	//       relay1 ---------->  relay2
	//          ^                   ^
	//          |                   |
	//        node1               node2
	//

	testScenario := scenario{
		netConfig: networkConfiguration{
			nodes: []nodeConfiguration{
				{
					name:    "relay1",
					isRelay: true,
				},
				{
					name:    "relay2",
					isRelay: true,
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
					},
				},
				{
					name: "node1",
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
					},
				},
				{
					name: "node2",
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        1,
						},
					},
				},
			},
		},
		testDuration: 1000 * time.Millisecond,
		initialAlloc: []initialTransactionsAllocation{
			initialTransactionsAllocation{
				node:              2,
				transactionsCount: 1,
				transactionSize:   250,
				expirationRound:   basics.Round(5),
			},
		},
		expectedResults: emulatorResult{
			nodes: []nodeTransactions{
				{
					nodeTransaction{
						expirationRound: 5,
						transactionSize: 250,
					},
				},
				{
					nodeTransaction{
						expirationRound: 5,
						transactionSize: 250,
					},
				},
				{
					nodeTransaction{
						expirationRound: 5,
						transactionSize: 250,
					},
				},
				{
					nodeTransaction{
						expirationRound: 5,
						transactionSize: 250,
					},
				},
			},
		},
		step: 1 * time.Millisecond,
	}
	emulateScenario(t, testScenario)
}

func TestEmulatedLargeSetTransactionsExchange(t *testing.T) {
	testScenario := scenario{
		netConfig: networkConfiguration{
			nodes: []nodeConfiguration{
				{
					name:    "relay",
					isRelay: true,
				},
				{
					name: "node",
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
					},
				},
			},
		},
		testDuration: 1000 * time.Millisecond,
		initialAlloc: []initialTransactionsAllocation{
			initialTransactionsAllocation{
				node:              1,
				transactionsCount: 100,
				transactionSize:   800,
				expirationRound:   basics.Round(5),
			},
		},
		expectedResults: emulatorResult{
			nodes: []nodeTransactions{
				{},
				{},
			},
		},
		step: 1 * time.Millisecond / 10,
	}
	// update the expected results to have the correct number of entries.
	for i := 0; i < testScenario.initialAlloc[0].transactionsCount; i++ {
		for n := range testScenario.expectedResults.nodes {
			testScenario.expectedResults.nodes[n] = append(testScenario.expectedResults.nodes[n], nodeTransaction{expirationRound: testScenario.initialAlloc[0].expirationRound, transactionSize: testScenario.initialAlloc[0].transactionSize})
		}
	}

	t.Run("NonRelay_To_Relay", func(t *testing.T) {
		testScenario.netConfig.nodes[0].name = "relay"
		testScenario.netConfig.nodes[0].isRelay = true
		testScenario.netConfig.nodes[1].name = "node"
		testScenario.initialAlloc[0].node = 1
		emulateScenario(t, testScenario)
	})

	t.Run("Relay_To_NonRelay", func(t *testing.T) {
		testScenario.netConfig.nodes[0].name = "relay"
		testScenario.netConfig.nodes[0].isRelay = true
		testScenario.netConfig.nodes[1].name = "node"
		testScenario.initialAlloc[0].node = 0
		emulateScenario(t, testScenario)
	})

	t.Run("OutgoingRelay_To_IncomingRelay", func(t *testing.T) {
		testScenario.netConfig.nodes[0].name = "incoming-relay"
		testScenario.netConfig.nodes[0].isRelay = true
		testScenario.netConfig.nodes[1].name = "outgoing-relay"
		testScenario.netConfig.nodes[1].isRelay = true
		testScenario.initialAlloc[0].node = 1
		emulateScenario(t, testScenario)
	})

	t.Run("OutgoingRelay_To_IncomingRelay", func(t *testing.T) {
		testScenario.netConfig.nodes[0].name = "incoming-relay"
		testScenario.netConfig.nodes[0].isRelay = true
		testScenario.netConfig.nodes[1].name = "outgoing-relay"
		testScenario.netConfig.nodes[1].isRelay = true
		testScenario.initialAlloc[0].node = 0
		emulateScenario(t, testScenario)
	})
}

func TestEmulatedLargeSetTransactionsExchangeIntermixed(t *testing.T) {
	testScenario := scenario{
		netConfig: networkConfiguration{
			nodes: []nodeConfiguration{
				{
					name:    "relay",
					isRelay: true,
				},
				{
					name: "node",
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
					},
				},
			},
		},
		initialAlloc: []initialTransactionsAllocation{
			initialTransactionsAllocation{
				node:              0,
				transactionsCount: 200,
				transactionSize:   400,
				expirationRound:   basics.Round(5),
			},
			initialTransactionsAllocation{
				node:              1,
				transactionsCount: 100,
				transactionSize:   800,
				expirationRound:   basics.Round(5),
			},
		},
		expectedResults: emulatorResult{
			nodes: []nodeTransactions{
				{},
				{},
			},
		},
		step:         1 * time.Millisecond / 10,
		testDuration: 1200 * time.Millisecond,
	}
	// update the expected results to have the correct number of entries.
	for j := range testScenario.initialAlloc {
		for i := 0; i < testScenario.initialAlloc[j].transactionsCount; i++ {
			for n := range testScenario.expectedResults.nodes {
				testScenario.expectedResults.nodes[n] = append(testScenario.expectedResults.nodes[n], nodeTransaction{expirationRound: testScenario.initialAlloc[j].expirationRound, transactionSize: testScenario.initialAlloc[j].transactionSize})
			}
		}
	}

	t.Run("NonRelay_To_Relay", func(t *testing.T) {
		testScenario.netConfig.nodes[0].name = "relay"
		testScenario.netConfig.nodes[0].isRelay = true
		testScenario.netConfig.nodes[1].name = "node"
		testScenario.initialAlloc[0].node = 1
		emulateScenario(t, testScenario)
	})

	t.Run("Relay_To_NonRelay", func(t *testing.T) {
		testScenario.netConfig.nodes[0].name = "relay"
		testScenario.netConfig.nodes[0].isRelay = true
		testScenario.netConfig.nodes[1].name = "node"
		testScenario.initialAlloc[0].node = 0
		emulateScenario(t, testScenario)
	})

	t.Run("OutgoingRelay_To_IncomingRelay", func(t *testing.T) {
		testScenario.netConfig.nodes[0].name = "incoming-relay"
		testScenario.netConfig.nodes[0].isRelay = true
		testScenario.netConfig.nodes[1].name = "outgoing-relay"
		testScenario.netConfig.nodes[1].isRelay = true
		testScenario.initialAlloc[0].node = 1
		emulateScenario(t, testScenario)
	})

	t.Run("IncomingRelay_To_OutgoingRelay", func(t *testing.T) {
		testScenario.netConfig.nodes[0].name = "incoming-relay"
		testScenario.netConfig.nodes[0].isRelay = true
		testScenario.netConfig.nodes[1].name = "outgoing-relay"
		testScenario.netConfig.nodes[1].isRelay = true
		testScenario.initialAlloc[0].node = 0
		emulateScenario(t, testScenario)
	})
}

func TestEmulatedNonRelayToMultipleRelays(t *testing.T) {
	testScenario := scenario{
		netConfig: networkConfiguration{
			nodes: []nodeConfiguration{
				{
					name:    "relay-1",
					isRelay: true,
				},
				{
					name:    "relay-2",
					isRelay: true,
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
					},
				},
				{
					name:    "relay-3",
					isRelay: true,
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        1,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
					},
				},
				{
					name: "node-1",
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        1,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        2,
						},
					},
				},
				{
					name: "node-2",
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        2,
						},
					},
				},
			},
		},
		initialAlloc: []initialTransactionsAllocation{
			initialTransactionsAllocation{
				node:              4, // i.e. node-2
				transactionsCount: 1000,
				transactionSize:   250,
				expirationRound:   basics.Round(5),
			},
		},
		expectedResults: emulatorResult{
			nodes: []nodeTransactions{
				{},
				{},
				{},
				{},
				{},
			},
		},
		step:         1 * time.Millisecond / 10,
		testDuration: 2000 * time.Millisecond,
	}
	// update the expected results to have the correct number of entries.
	for j := range testScenario.initialAlloc {
		for i := 0; i < testScenario.initialAlloc[j].transactionsCount; i++ {
			for n := range testScenario.expectedResults.nodes {
				testScenario.expectedResults.nodes[n] = append(testScenario.expectedResults.nodes[n], nodeTransaction{expirationRound: testScenario.initialAlloc[j].expirationRound, transactionSize: testScenario.initialAlloc[j].transactionSize})
			}
		}
	}

	emulateScenario(t, testScenario)
}

func TestEmulatedTwoNodesFourRelays(t *testing.T) {
	testScenario := scenario{
		netConfig: networkConfiguration{
			nodes: []nodeConfiguration{
				{
					name:    "relay-1",
					isRelay: true,
				},
				{
					name:    "relay-2",
					isRelay: true,
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        3,
						},
					},
				},
				{
					name:    "relay-3",
					isRelay: true,
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        1,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
					},
				},
				{
					name:    "relay-4",
					isRelay: true,
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        2,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
					},
				},
				{
					name: "node-1",
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        1,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        2,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        3,
						},
					},
				},
				{
					name: "node-2",
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        1,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        2,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        3,
						},
					},
				},
			},
		},
		initialAlloc: []initialTransactionsAllocation{
			initialTransactionsAllocation{
				node:              4, // i.e. node-1
				transactionsCount: 3000,
				transactionSize:   270,
				expirationRound:   basics.Round(5),
			},
			initialTransactionsAllocation{
				node:              5, // i.e. node-2
				transactionsCount: 1500,
				transactionSize:   320,
				expirationRound:   basics.Round(5),
			},
		},
		expectedResults: emulatorResult{
			nodes: []nodeTransactions{
				{},
				{},
				{},
				{},
				{},
				{},
			},
		},
		step:         1 * time.Millisecond / 10,
		testDuration: 2100 * time.Millisecond,
	}
	// update the expected results to have the correct number of entries.
	for j := range testScenario.initialAlloc {
		for i := 0; i < testScenario.initialAlloc[j].transactionsCount; i++ {
			for n := range testScenario.expectedResults.nodes {
				testScenario.expectedResults.nodes[n] = append(testScenario.expectedResults.nodes[n], nodeTransaction{expirationRound: testScenario.initialAlloc[j].expirationRound, transactionSize: testScenario.initialAlloc[j].transactionSize})
			}
		}
	}

	emulateScenario(t, testScenario)
}

func TestEmulatedTwentyNodesFourRelays(t *testing.T) {
	if testing.Short() {
		t.Skip("TestEmulatedTwentyNodesFourRelays is a long test and therefore was skipped")
	}
	testScenario := scenario{
		netConfig: networkConfiguration{
			nodes: []nodeConfiguration{
				{
					name:    "relay-1",
					isRelay: true,
				},
				{
					name:    "relay-2",
					isRelay: true,
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        3,
						},
					},
				},
				{
					name:    "relay-3",
					isRelay: true,
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        1,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
					},
				},
				{
					name:    "relay-4",
					isRelay: true,
					outgoingConnections: []connectionSettings{
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        2,
						},
						{
							uploadSpeed:   1000000,
							downloadSpeed: 1000000,
							target:        0,
						},
					},
				},
			},
		},
		initialAlloc: []initialTransactionsAllocation{},
		expectedResults: emulatorResult{
			nodes: []nodeTransactions{
				{},
				{},
				{},
				{},
			},
		},
		step:         1 * time.Millisecond / 10,
		testDuration: 2000 * time.Millisecond,
	}

	// add nodes.
	for i := 0; i < 20; i++ {
		testScenario.netConfig.nodes = append(testScenario.netConfig.nodes, nodeConfiguration{
			name: fmt.Sprintf("node-%d", i+1),
			outgoingConnections: []connectionSettings{
				{
					uploadSpeed:   1000000,
					downloadSpeed: 1000000,
					target:        0,
				},
				{
					uploadSpeed:   1000000,
					downloadSpeed: 1000000,
					target:        1,
				},
				{
					uploadSpeed:   1000000,
					downloadSpeed: 1000000,
					target:        2,
				},
				{
					uploadSpeed:   1000000,
					downloadSpeed: 1000000,
					target:        3,
				},
			},
		})

		testScenario.initialAlloc = append(testScenario.initialAlloc, initialTransactionsAllocation{
			node:              4 + i, // i.e. node-1 + i
			transactionsCount: 250,
			transactionSize:   270,
			expirationRound:   basics.Round(5),
		})

		testScenario.expectedResults.nodes = append(testScenario.expectedResults.nodes, nodeTransactions{})
	}

	// update the expected results to have the correct number of entries.
	for j := range testScenario.initialAlloc {
		for i := 0; i < testScenario.initialAlloc[j].transactionsCount; i++ {
			for n := range testScenario.expectedResults.nodes {
				testScenario.expectedResults.nodes[n] = append(testScenario.expectedResults.nodes[n], nodeTransaction{expirationRound: testScenario.initialAlloc[j].expirationRound, transactionSize: testScenario.initialAlloc[j].transactionSize})
			}
		}
	}

	emulateScenario(t, testScenario)
}
