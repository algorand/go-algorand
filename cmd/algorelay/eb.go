package main

import "time"

const NodeRunnerKind = "NodeRunner"

// NodeRunner entities are synchronized directly from db1 using `afdb1 syncebnoderunners`
// They should not be modified manually
type NodeRunner struct {
	CompanyName      string
	InvestorID       string
	NbRequiredRelays int    // number of relays required relays the investor needs to run in the node agreement
	NodeRunnerToken  string // token used by eb.algorand.foundation
}

const RelayKind = "Relay"

type Relay struct {
	InvestorID            string
	ContactEmail          string // comma separated list of emails
	NodeProvider          string
	IPOrDNSName           string
	Specs                 string
	Notes                 string
	SubmissionTime        time.Time
	SRVRecordCreationTime time.Time
	Telemetry             string // GUID[:name]
	MetricsEnabled        bool
}
