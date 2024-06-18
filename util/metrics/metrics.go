// Copyright (C) 2019-2024 Algorand, Inc.
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
	// DuplicateNetworkFilterReceivedTotal Total number of duplicate filter messages (tag MsgDigestSkipTag) that were received from the network
	DuplicateNetworkFilterReceivedTotal = MetricName{Name: "algod_network_duplicate_filter_received_total", Description: "Total number of duplicate filter messages that were received from the network"}
	// OutgoingNetworkMessageFilteredOutTotal Total number of messages that were not sent per peer request
	OutgoingNetworkMessageFilteredOutTotal = MetricName{Name: "algod_outgoing_network_message_filtered_out_total", Description: "Total number of messages that were not sent per peer request"}
	// OutgoingNetworkMessageFilteredOutBytesTotal Total number of bytes saved by not sending messages that were asked not to be sent by peer
	OutgoingNetworkMessageFilteredOutBytesTotal = MetricName{Name: "algod_outgoing_network_message_filtered_out_bytes_total", Description: "Total number of bytes saved by not sending messages that were asked not to be sent by peer"}
	// UnknownProtocolTagMessagesTotal Total number of out-of-protocol tag messages received from the network
	UnknownProtocolTagMessagesTotal = MetricName{Name: "algod_network_unk_tag_messages_total", Description: "Total number of unknown protocol tag messages received from the network"}
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
	// LedgerDBRound Last round written to ledger
	LedgerDBRound = MetricName{Name: "algod_ledger_dbround", Description: "Last round written to the ledger DB"}

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
	// TransactionMessagesAlreadyCommitted "Number of duplicate or error transaction messages before placing into a backlog"
	TransactionMessagesAlreadyCommitted = MetricName{Name: "algod_transaction_messages_err_or_committed", Description: "Number of duplicate or error transaction messages after TX handler backlog"}
	// TransactionMessagesTxGroupInvalidFee "Number of transaction messages with invalid txgroup fee"
	TransactionMessagesTxGroupInvalidFee = MetricName{Name: "algod_transaction_messages_txgroup_invalid_fee", Description: "Number of transaction messages with invalid txgroup fee"}
	// TransactionMessagesTxnDroppedCongestionManagement "Number of transaction messages dropped because the tx backlog is under congestion management"
	TransactionMessagesTxnDroppedCongestionManagement = MetricName{Name: "algod_transaction_messages_txn_dropped_congestion_ctrl", Description: "Number of transaction messages dropped because the tx backlog is under congestion management"}
	// TransactionMessagesTxnNotWellFormed "Number of transaction messages not well formed"
	TransactionMessagesTxnNotWellFormed = MetricName{Name: "algod_transaction_messages_txn_notwell_formed", Description: "Number of transaction messages not well formed"}
	// TransactionMessagesTxnSigNotWellFormed "Number of transaction messages with bad formed signature"
	TransactionMessagesTxnSigNotWellFormed = MetricName{Name: "algod_transaction_messages_sig_bad_formed", Description: "Number of transaction messages with bad formed signature"}
	// TransactionMessagesTxnMsigNotWellFormed "Number of transaction messages with bad formed multisig"
	TransactionMessagesTxnMsigNotWellFormed = MetricName{Name: "algod_transaction_messages_msig_bad_formed", Description: "Number of transaction messages with bad formed msig"}
	// TransactionMessagesTxnLogicSig "Number of transaction messages with invalid logic sig"
	TransactionMessagesTxnLogicSig = MetricName{Name: "algod_transaction_messages_logic_sig_failed", Description: "Number of transaction messages with invalid logic sig"}
	// TransactionMessagesTxnSigVerificationFailed "Number of transaction messages with signature verification failed"
	TransactionMessagesTxnSigVerificationFailed = MetricName{Name: "algod_transaction_messages_sig_verify_failed", Description: "Number of transaction messages with signature verification failed"}
	// TransactionMessagesBacklogErr "Number of transaction messages with some validation error"
	TransactionMessagesBacklogErr = MetricName{Name: "algod_transaction_messages_backlog_err", Description: "Number of transaction messages with some validation error"}
	// TransactionMessagesRemember "Number of transaction messages remembered in TX handler"
	TransactionMessagesRemember = MetricName{Name: "algod_transaction_messages_remember", Description: "Number of transaction messages remembered in TX handler"}
	// TransactionMessageTxGroupFull "Number of transaction messages with max txns allowed"
	TransactionMessageTxGroupFull = MetricName{Name: "algod_transaction_messages_txgroup_full", Description: "Number of transaction messages with max txns allowed"}
	// TransactionMessageTxGroupExcessive "Number of transaction messages with greater than max allowed txns"
	TransactionMessageTxGroupExcessive = MetricName{Name: "algod_transaction_messages_txgroup_excessive", Description: "Number of transaction messages with greater than max allowed txns"}
	// TransactionMessagesDupRawMsg "Number of dupe raw transaction messages dropped"
	TransactionMessagesDupRawMsg = MetricName{Name: "algod_transaction_messages_dropped_dup_raw", Description: "Number of dupe raw transaction messages dropped"}
	// TransactionMessagesDupCanonical "Number of transaction messages dropped after canonical re-encoding"
	TransactionMessagesDupCanonical = MetricName{Name: "algod_transaction_messages_dropped_dup_canonical", Description: "Number of transaction messages dropped after canonical re-encoding"}
	// TransactionMessagesAppLimiterDrop "Number of transaction messages dropped after app limits check"
	TransactionMessagesAppLimiterDrop = MetricName{Name: "algod_transaction_messages_dropped_app_limiter", Description: "Number of transaction messages dropped after app limits check"}
	// TransactionMessagesBacklogSize "Number of transaction messages in the TX handler backlog queue"
	TransactionMessagesBacklogSize = MetricName{Name: "algod_transaction_messages_backlog_size", Description: "Number of transaction messages in the TX handler backlog queue"}

	// TransactionGroupTxSyncHandled "Number of transaction groups handled via txsync"
	TransactionGroupTxSyncHandled = MetricName{Name: "algod_transaction_group_txsync_handled", Description: "Number of transaction groups handled via txsync"}
	// TransactionGroupTxSyncRemember "Number of transaction groups remembered via txsync"
	TransactionGroupTxSyncRemember = MetricName{Name: "algod_transaction_group_txsync_remember", Description: "Number of transaction groups remembered via txsync"}
	// TransactionGroupTxSyncAlreadyCommitted "Number of duplicate or error transaction groups received via txsync"
	TransactionGroupTxSyncAlreadyCommitted = MetricName{Name: "algod_transaction_group_txsync_err_or_committed", Description: "Number of duplicate or error transaction groups received via txsync"}

	// BroadcastSignedTxGroupSucceeded "Number of successful broadcasts of local signed transaction groups"
	BroadcastSignedTxGroupSucceeded = MetricName{Name: "algod_broadcast_txgroup_succeeded", Description: "Number of successful broadcasts of local signed transaction groups"}
	// BroadcastSignedTxGroupFailed "Number of failed broadcasts of local signed transaction groups"
	BroadcastSignedTxGroupFailed = MetricName{Name: "algod_broadcast_txgroup_failed", Description: "Number of failed broadcasts of local signed transaction groups"}
)
