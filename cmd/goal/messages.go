// Copyright (C) 2019-2025 Algorand, Inc.
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

const (
	// General
	errorNoDataDirectory        = "Data directory not specified.  Please use -d or set $ALGORAND_DATA in your environment. Exiting."
	errorOneDataDirSupported    = "Only one data directory can be specified for this command."
	errorRequestFail            = "Error processing command: %s"
	errorGenesisIDFail          = "Error determining kmd folder (%s). Ensure the node is running in %s."
	errorDirectoryNotExist      = "Specified directory '%s' does not exist."
	errorParseAddr              = "Failed to parse addr: %v"
	errorNonPrintableCharacters = "One or more non-printable characters were omitted from the following error message:"
	infoNonPrintableCharacters  = "One or more non-printable characters were omitted from the subsequent line:"

	// Account
	infoNoAccounts                 = "Did not find any account. Please import or create a new one."
	infoRenamedAccount             = "Renamed account '%s' to '%s'"
	infoImportedKey                = "Imported %s"
	infoExportedKey                = "Exported key for account %s: \"%s\""
	infoImportedNKeys              = "Imported %d key%s"
	infoCreatedNewAccount          = "Created new account with address %s"
	errorNameAlreadyTaken          = "The account name '%s' is already taken, please choose another."
	errorNameDoesntExist           = "An account named '%s' does not exist."
	infoSetAccountToDefault        = "Set account '%s' to be the default account"
	errorSigningTX                 = "Couldn't sign tx with kmd: %s (for multisig accounts, write tx to file and sign manually)"
	errorConstructingTX            = "Couldn't construct tx: %s"
	errorBroadcastingTX            = "Couldn't broadcast tx with algod: %s"
	warnMultisigDuplicatesDetected = "Warning: one or more duplicate addresses detected in multisig account creation. This will effectively give the duplicated address(es) extra signature weight. Continuing multisig account creation."
	errLastRoundInvalid            = "roundLastValid needs to be well after the current round (%d)"
	errExistingPartKey             = "Account already has a participation key valid at least until roundLastValid (%d) - current is %d"
	errorSeedConversion            = "Got private key for account %s, but was unable to convert to seed: %s"
	errorMnemonicConversion        = "Got seed for account %s, but was unable to convert to mnemonic: %s"

	// KMD
	infoKMDStopped        = "Stopped kmd"
	infoKMDAlreadyStarted = "kmd is already running"
	infoKMDAlreadyStopped = "kmd doesn't appear to be running"
	infoKMDStarted        = "Successfully started kmd"
	errorKMDFailedToStart = "Failed to start kmd: %s"
	errorKMDFailedToStop  = "Failed to stop kmd: %s"

	// Node
	infoNodeStart                           = "Algorand node successfully started!"
	infoNodeAlreadyStarted                  = "Algorand node was already started!"
	infoNodeDidNotRestart                   = "Algorand node did not restart. The node is still running!"
	infoTryingToStopNode                    = "Trying to stop the node..."
	infoNodeShuttingDown                    = "Algorand node is shutting down..."
	infoNodeSuccessfullyStopped             = "The node was successfully stopped."
	infoNodeStatus                          = "Last committed block: %d\nTime since last block: %s\nSync Time: %s\nLast consensus protocol: %s\nNext consensus protocol: %s\nRound for next consensus protocol: %d\nNext consensus protocol supported: %v"
	infoNodeStatusConsensusUpgradeVoting    = "Consensus upgrade state: Voting\nYes votes: %d\nNo votes: %d\nVotes remaining: %d\nYes votes required: %d\nVote window close round: %d"
	infoNodeStatusConsensusUpgradeScheduled = "Consensus upgrade state: Scheduled"
	catchupStoppedOnUnsupported             = "Last supported block (%d) is committed. The next block consensus protocol is not supported. Catchup service is stopped."
	infoNodeCatchpointCatchupStatus         = "Last committed block: %d\nSync Time: %s\nCatchpoint: %s"
	infoNodeCatchpointCatchupAccounts       = "Catchpoint total accounts: %d\nCatchpoint accounts processed: %d\nCatchpoint accounts verified: %d\nCatchpoint total KVs: %d\nCatchpoint KVs processed: %d\nCatchpoint KVs verified: %d"
	infoNodeCatchpointCatchupBlocks         = "Catchpoint total blocks: %d\nCatchpoint downloaded blocks: %d"
	nodeLastCatchpoint                      = "Last Catchpoint: %s"
	nodeConfirmImplicitCatchpoint           = "Fast catchup to %s is about to start.\nUsing external catchpoints is not a secure practice and should not be done for consensus participating nodes.\nType 'yes' to accept the risk and continue: "
	errorAbortedPerUserRequest              = "Aborted"
	errorNodeCreationIPFailure              = "Parsing passed IP %v failed: need a valid IPv4 or IPv6 address with a specified port number"
	errorNodeNotDetected                    = "Algorand node does not appear to be running: %s"
	errorNodeStatus                         = "Cannot contact Algorand node: %s"
	errorNodePeers                          = "Cannot retrieve node peers: %s"
	errorNodeFailedToStart                  = "Algorand node failed to start: %s"
	errorNodeRunning                        = "Node must be stopped before writing APIToken"
	errorNodeFailGenToken                   = "Cannot generate API token: %s"
	errorNodeCreation                       = "Error during node creation: %v"
	errorNodeManagedBySystemd               = "This node is using systemd and should be managed with systemctl. For additional information refer to https://developer.algorand.org/docs/run-a-node/setup/install/#installing-algod-as-a-systemd-service"
	errorKill                               = "Cannot kill node: %s"
	errorCloningNode                        = "Error cloning the node: %s"
	infoNodeCloned                          = "Node cloned successfully to: %s"
	infoNodeWroteToken                      = "Successfully wrote new API token: %s"
	infoNodePendingTxnsDescription          = "Pending Transactions (Truncated max=%d, Total in pool=%d): "
	infoNodeNoPendingTxnsDescription        = "None"
	infoDataDir                             = "[Data Directory: %s]"
	errLoadingConfig                        = "Error loading Config file from '%s': %v"
	errorNodeFailedToShutdown               = "Unable to shut down node: %v"
	errorCatchpointLabelParsingFailed       = "The provided catchpoint is not a valid one"
	errorCatchpointLabelMissing             = "A catchpoint argument is needed: %s: %s"
	errorUnableToLookupCatchpointLabel      = "Unable to fetch catchpoint label"
	errorTooManyCatchpointLabels            = "The catchup command expect a single catchpoint"

	// Asset
	malformedMetadataHash = "Cannot base64-decode metadata hash %s: %s"

	// Application
	errorLocalGlobal               = "Exactly one of --local or --global is required"
	errorLocalStateRequiresAccount = "--local requires --from account"
	errorAccountNotOptedInToApp    = "%s has not opted in to application %d"
	errorNoSuchApplication         = "application %d does not exist"
	errorMarshalingState           = "failed to encode state: %s"
	errorApprovProgArgsRequired    = "Exactly one of --approval-prog or --approval-prog-raw is required"
	errorClearProgArgsRequired     = "Exactly one of --clear-prog or --clear-prog-raw is required"
	errorMissingBoxName            = "Box --name is required"
	errorInvalidBoxName            = "Failed to parse box name %s. It must have the same form as app-arg. Error: %s"
	errorBoxNameMismatch           = "Inputted box name %s does not match box name %s received from algod"

	// Clerk
	infoTxIssued               = "Sent %d MicroAlgos from account %s to address %s, transaction ID: %s. Fee set to %d"
	infoTxCommitted            = "Transaction %s committed in round %d"
	infoTxPending              = "Transaction %s still pending as of round %d"
	malformedNote              = "Cannot base64-decode note %s: %s"
	malformedLease             = "Cannot base64-decode lease %s: %s"
	fileReadError              = "Cannot read file %s: %s"
	fileWriteError             = "Cannot write file %s: %s"
	txDecodeError              = "Cannot decode transactions from %s: %s"
	txDupError                 = "Duplicate transaction %s in %s"
	txLengthError              = "Transaction list length mismatch"
	txMergeMismatch            = "Cannot merge transactions: transaction IDs differ"
	txMergeError               = "Cannot merge signatures: %v"
	txNoFilesError             = "No input filenames specified"
	soFlagError                = "-s is not meaningful without -o"
	infoRawTxIssued            = "Raw transaction ID %s issued"
	txPoolError                = "Transaction %s kicked out of local node pool: %s"
	addrNoSigError             = "Exactly one of --address or --no-sig is required"
	msigLookupError            = "Could not lookup multisig information: %s"
	msigParseError             = "Multisig information parsing error: %s"
	failDecodeAddressError     = "Cannot decode address: %v"
	rekeySenderTargetSameError = "The sender and the resulted multisig address are the same"
	noOutputFileError          = "--msig-params must be specified with an output file name (-o)"
	infoAutoFeeSet             = "Automatically set fee to %d MicroAlgos"
	errorTransactionExpired    = "Transaction %s expired before it could be included in a block"

	loggingNotConfigured = "Remote logging is not currently configured and won't be enabled"
	loggingNotEnabled    = "Remote logging is current disabled"
	loggingEnabled       = "Remote logging is enabled.  Node = %s, Guid = %s"

	infoNetworkAlreadyExists = "Network Root Directory '%s' already exists and is not empty"
	errorCreateNetwork       = "Error creating private network: %s"
	infoNetworkCreated       = "Network %s created under %s"
	errorLoadingNetwork      = "Error loading deployed network: %s"
	errorStartingNetwork     = "Error starting deployed network: %s"
	infoNetworkStarted       = "Network Started under %s"
	infoNetworkStopped       = "Network Stopped under %s"
	infoNetworkDeleted       = "Network Deleted under %s"

	multisigProgramCollision = "should have at most one of --program/-p | --program-bytes/-P | --lsig/-L"

	tealsignMutKeyArgs    = "Need exactly one of --keyfile or --account"
	tealsignMutLsigArgs   = "Need exactly one of --contract-addr or --lsig-txn"
	tealsignKeyfileFail   = "Failed to read keyfile: %v"
	tealsignNoWithAcct    = "--account is not yet supported"
	tealsignEmptyLogic    = "LogicSig must have non-empty program"
	tealsignParseAddr     = "Failed to parse contract addr: %v"
	tealsignParseData     = "Failed to parse data to sign: %v"
	tealsignParseb64      = "failed to base64 decode data to sign: %v"
	tealsignParseb32      = "failed to base32 decode data to sign: %v"
	tealsignTxIDLsigReq   = "--sign-txid requires --lsig-txn"
	tealsignSetArgLsigReq = "--set-lsig-arg-idx requires --lsig-txn"
	tealsignDataReq       = "need exactly one of --sign-txid, --data-file, --data-b64, or --data-b32"
	tealsignInfoSig       = "Generated signature: %s"
	tealsignTooManyArg    = "--set-lsig-arg-idx too large, maximum of %d arguments"
	tealsignInfoWroteSig  = "Wrote signature for %s to LSig.Args[%d]"

	// Wallet
	infoRecoveryPrompt           = "Please type your recovery mnemonic below, and hit return when you are done: "
	infoChoosePasswordPrompt     = "Please choose a password for wallet '%s': "
	infoPasswordConfirmation     = "Please confirm the password: "
	infoCreatingWallet           = "Creating wallet..."
	infoCreatedWallet            = "Created wallet '%s'"
	infoUnencrypted              = "Creating unencrypted wallet"
	infoBackupExplanation        = "Your new wallet has a backup phrase that can be used for recovery.\nKeeping this backup phrase safe is extremely important.\nWould you like to see it now? (Y/n): "
	infoPrintedBackupPhrase      = "Your backup phrase is printed below.\nKeep this information safe -- never share it with anyone!"
	infoBackupPhrase             = "\n%s"
	infoNoWallets                = "No wallets found. You can create a wallet with `goal wallet new`"
	infoRenamedWallet            = "Renamed wallet '%s' to '%s'"
	errorCouldntCreateWallet     = "Couldn't create wallet: %s"
	errorCouldntInitializeWallet = "Couldn't initialize wallet: %s"
	errorCouldntExportMDK        = "Couldn't export master derivation key: %s"
	errorCouldntMakeMnemonic     = "Couldn't make mnemonic: %s"
	errorCouldntListWallets      = "Couldn't list wallets: %s"
	errorCouldntFindWallet       = "Couldn't find wallet: %s"
	errorPasswordConfirmation    = "Password confirmation did not match"
	errorBadMnemonic             = "Problem with mnemonic: %s"
	errorBadRecoveredKey         = "Recovered invalid key"
	errorFailedToReadResponse    = "Couldn't read response: %s"
	errorFailedToReadPassword    = "Couldn't read password: %s"
	errorCouldntRenameWallet     = "Couldn't rename wallet: %s"

	// Commands
	infoPasswordPrompt       = "Please enter the password for wallet '%s': "
	infoSetWalletToDefault   = "Set wallet '%s' to be the default wallet"
	errCouldNotListWallets   = "Couldn't list wallets: %s"
	errNoWallets             = "No wallets found. Create a new wallet with `goal wallet new [wallet name]`"
	errNoDefaultWallet       = "No default wallet found. Specify a wallet by name with -w, or set a default with `goal wallet -f [wallet name]"
	errFindingWallet         = "Couldn't find wallet: %s"
	errWalletNameAmbiguous   = "More than one wallet named '%s' exists. Please remove any wallets with the same name from the kmd wallet directory"
	errWalletIDDuplicate     = "More than one wallet with ID '%s' exists. Please remove any wallets with the samd ID from the kmd wallet directory"
	errGettingWalletName     = "Couldn't get wallet name from ID '%s': %s"
	errWalletNotFound        = "Wallet '%s' not found"
	errDefaultWalletNotFound = "Wallet with ID '%s' not found. Was the default wallet deleted?"
	errGettingToken          = "Couldn't get token for wallet '%s' (ID: %s): %s"

	// Ledger
	errParsingRoundNumber  = "Error parsing round number: %s"
	errBadBlockArgs        = "Cannot combine --b32=true or --strict=true with --raw"
	errEncodingBlockAsJSON = "Error encoding block as json: %s"
)
