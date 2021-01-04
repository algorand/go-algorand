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

package metrics

// MetricName describes the name and description of a single metric
type MetricName struct {
	Name        string
	Description string
}

var (
	// NetworkIncomingConnections Number of incoming connections
	NetworkIncomingConnections = MetricName{Name: "algod_network_incoming_connections", Description: "Number of incoming connections"}
	// NetworkOutgoingConnections Number of outgoing connections
	NetworkOutgoingConnections = MetricName{Name: "algod_network_outgoing_connections", Description: "Number of outgoing connections"}
	// NetworkOutgoingUniqueConnections Total number of unique outgoing addresses connections ever seen by node.
	NetworkOutgoingUniqueConnections = MetricName{Name: "algod_network_unique_outgoing_connections", Description: "Number of unique outgoing connections"}
	// NetworkPeersGarbageCollected How many peers were not caught by event-based cleanup but instead polling garbage collection thread.
	NetworkPeersGarbageCollected = MetricName{Name: "algod_network_peer_gc", Description: "Number of peers garbage collected instead of normal inline close flow"}
	// NetworkSentBytesTotal Total number of bytes that were sent over the network
	NetworkSentBytesTotal = MetricName{Name: "algod_network_sent_bytes_total", Description: "Total number of bytes that were sent over the network"}
	// NetworkReceivedBytesTotal Total number of bytes that were received from the network
	NetworkReceivedBytesTotal = MetricName{Name: "algod_network_received_bytes_total", Description: "Total number of bytes that were received from the network"}
	// NetworkMessageReceivedTotal Total number of complete messages that were received from the network
	NetworkMessageReceivedTotal = MetricName{Name: "algod_network_message_received_total", Description: "Total number of complete messages that were received from the network"}
	// NetworkMessageSentTotal Total number of complete messages that were sent to the network
	NetworkMessageSentTotal = MetricName{Name: "algod_network_message_sent_total", Description: "Total number of complete messages that were sent to the network"}
	// NetworkConnectionsDroppedTotal Total number of connections that were dropped before a message
	NetworkConnectionsDroppedTotal = MetricName{Name: "algod_network_connections_dropped_total", Description: "Total number of connections that were dropped before a message"}
	// NetworkSentDecompressedBytesTotal Total number of bytes that were sent over the network prior of being compressed
	NetworkSentDecompressedBytesTotal = MetricName{Name: "algod_network_sent_decompressed_bytes_total", Description: "Total number of bytes that were sent over the network prior of being compressed"}
	// NetworkReceivedDecompressedBytesTotal Total number of bytes that were received from the network after of being decompressed
	NetworkReceivedDecompressedBytesTotal = MetricName{Name: "algod_network_received_decompressed_bytes_total", Description: "Total number of bytes that were received from the network after being decompressed"}
	// DuplicateNetworkMessageReceivedTotal Total number of duplicate messages that were received from the network
	DuplicateNetworkMessageReceivedTotal = MetricName{Name: "algod_network_duplicate_message_received_total", Description: "Total number of duplicate messages that were received from the network"}
	// DuplicateNetworkMessageReceivedBytesTotal The total number ,in bytes, of the duplicate messages that were received from the network
	DuplicateNetworkMessageReceivedBytesTotal = MetricName{Name: "algod_network_duplicate_message_received_bytes_total", Description: "The total number ,in bytes, of the duplicate messages that were received from the network"}
	// OutgoingNetworkMessageFilteredOutTotal Total number of messages that were not sent per peer request
	OutgoingNetworkMessageFilteredOutTotal = MetricName{Name: "algod_outgoing_network_message_filtered_out_total", Description: "Total number of messages that were not sent per peer request"}
	// OutgoingNetworkMessageFilteredOutBytesTotal Total number of bytes saved by not sending messages that were asked not to be sent by peer
	OutgoingNetworkMessageFilteredOutBytesTotal = MetricName{Name: "algod_outgoing_network_message_filtered_out_bytes_total", Description: "Total number of bytes saved by not sending messages that were asked not to be sent by peer"}
	// CryptoGenSigSecretsTotal Total number of calls to GenerateSignatureSecrets()
	CryptoGenSigSecretsTotal = MetricName{Name: "algod_crypto_signature_secrets_generate_total", Description: "Total number of calls to GenerateSignatureSecrets"}
	// CryptoSigSecretsSignTotal Total number of calls to SignatureSecrets.Sign
	CryptoSigSecretsSignTotal = MetricName{Name: "algod_crypto_signature_secrets_sign_total", Description: "Total number of calls to SignatureSecrets.Sign"}
	// CryptoSigSecretsSignBytesTotal Total number of calls to SignatureSecrets.signBytes
	CryptoSigSecretsSignBytesTotal = MetricName{Name: "algod_crypto_signature_secrets_bytes_sign_total", Description: "Total number of calls to SignatureSecrets.signBytes"}
	// CryptoSigSecretsVerifyTotal Total number of calls to SignatureVerifier.Verify
	CryptoSigSecretsVerifyTotal = MetricName{Name: "algod_crypto_signature_secrets_verify_total", Description: "Total number of calls to SignatureVerifier.Verify"}
	// CryptoVRFGenerateTotal Total number of calls to GenerateVRFSecrets()
	CryptoVRFGenerateTotal = MetricName{Name: "algod_crypto_vrf_generate_total", Description: "Total number of calls to GenerateVRFSecrets"}
	// CryptoVRFProveTotal Total number of calls to VRFSecrets.Prove
	CryptoVRFProveTotal = MetricName{Name: "algod_crypto_vrf_prove_total", Description: "Total number of calls to VRFSecrets.Prove"}
	// CryptoVRFHashTotal Total number of calls to VRFProof.Hash
	CryptoVRFHashTotal = MetricName{Name: "algod_crypto_vrf_hash_total", Description: "Total number of calls to VRFProof.Hash"}
	// CryptoVRFVerifyTotal Total number of calls to VRFVerifier.Verify
	CryptoVRFVerifyTotal = MetricName{Name: "algod_crypto_vrf_verify_total", Description: "Total number of calls to VRFVerifier.Verify"}
	// CryptoSigSecretsVerifyBytesTotal Total number of calls to SignatureVerifier.VerifyBytes
	CryptoSigSecretsVerifyBytesTotal = MetricName{Name: "algod_crypto_vrf_bytes_verify_total", Description: "Total number of calls to SignatureVerifier.VerifyBytes"}
	// LedgerTransactionsTotal Total number of transactions written to the ledger
	LedgerTransactionsTotal = MetricName{Name: "algod_ledger_transactions_total", Description: "Total number of transactions written to the ledger"}
	// LedgerRewardClaimsTotal Total number of reward claims written to the ledger
	LedgerRewardClaimsTotal = MetricName{Name: "algod_ledger_reward_claims_total", Description: "Total number of reward claims written to the ledger"}
	// LedgerRound Last round written to ledger
	LedgerRound = MetricName{Name: "algod_ledger_round", Description: "Last round written to ledger"}

	// AgreementMessagesHandled "Number of agreement messages handled"
	AgreementMessagesHandled = MetricName{Name: "algod_agreement_handled", Description: "Number of agreement messages handled"}
	// AgreementMessagesDropped "Number of agreement messages dropped"
	AgreementMessagesDropped = MetricName{Name: "algod_agreement_dropped", Description: "Number of agreement messages dropped"}

	// TransactionMessagesHandled "Number of transaction messages handled"
	TransactionMessagesHandled = MetricName{Name: "algod_transaction_messages_handled", Description: "Number of transaction messages handled"}
	// TransactionMessagesDroppedFromBacklog "Number of transaction messages dropped from backlog"
	TransactionMessagesDroppedFromBacklog = MetricName{Name: "algod_transaction_messages_dropped_backlog", Description: "Number of transaction messages dropped from backlog"}
	// TransactionMessagesDroppedFromPool "Number of transaction messages dropped from pool"
	TransactionMessagesDroppedFromPool = MetricName{Name: "algod_transaction_messages_dropped_pool", Description: "Number of transaction messages dropped from pool"}
)
