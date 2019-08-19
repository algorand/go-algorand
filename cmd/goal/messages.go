// Copyright (C) 2019 Algorand, Inc.
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
	errorNoDataDirectory     = "Data directory not specified.  Please use -d or set $ALGORAND_DATA in your environment. Exiting."
	errorOneDataDirSupported = "Only one data directory can be specified for this command."
	errorRequestFail         = "Error processing command: %s"
	errorGenesisIDFail       = "Error determining kmd folder (%s). Ensure the node is running in %s."
	errorDirectoryNotExist   = "Specified directory '%s' does not exist."

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
	errorSigningTX                 = "Couldn't sign tx with kmd: %s"
	errorOnlineTX                  = "Couldn't sign tx: %s (for multisig accounts, write tx to file and sign manually)"
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
	infoNodeStart                    = "Algorand node successfully started!"
	infoNodeAlreadyStarted           = "Algorand node was already started!"
	infoTryingToStopNode             = "Trying to stop the node..."
	infoNodeSuccessfullyStopped      = "The node was successfully stopped."
	infoNodeStatus                   = "Last committed block: %d\nTime since last block: %s\nSync Time: %s\nLast consensus protocol: %s\nNext consensus protocol: %s\nRound for next consensus protocol: %d\nNext consensus protocol supported: %v\nHas Synced Since Startup: %t"
	errorNodeCreationIPFailure       = "Parsing passed IP %v failed: need a valid IPv4 or IPv6 address with a specified port number"
	errorNodeNotDetected             = "Algorand node does not appear to be running: %s"
	errorNodeStatus                  = "Cannot contact Algorand node: %s."
	errorNodeFailedToStart           = "Algorand node failed to start: %s"
	errorNodeRunning                 = "Node must be stopped before writing APIToken"
	errorNodeFailGenToken            = "Cannot generate API token: %s"
	errorNodeCreation                = "Error during node creation: %v"
	errorKill                        = "Cannot kill node: %s"
	errorCloningNode                 = "Error cloning the node: %s"
	infoNodeCloned                   = "Node cloned successfully to: %s"
	infoNodeWroteToken               = "Successfully wrote new API token: %s"
	infoNodePendingTxnsDescription   = "Pending Transactions (Truncated max=%d, Total in pool=%d): "
	infoNodeNoPendingTxnsDescription = "None"
	infoDataDir                      = "[Data Directory: %s]"
	errLoadingConfig                 = "Error loading Config file from '%s': %v"

	// Clerk
	infoTxIssued    = "Sent %d MicroAlgos from account %s to address %s, transaction ID: %s. Fee set to %d"
	infoTxCommitted = "Transaction %s committed in round %d"
	infoTxPending   = "Transaction %s still pending as of round %d"
	malformedNote   = "Cannot base64-decode note %s: %s"
	fileReadError   = "Cannot read file %s: %s"
	fileWriteError  = "Cannot write file %s: %s"
	txDecodeError   = "Cannot decode transactions from %s: %s"
	txDupError      = "Duplicate transaction %s in %s"
	txLengthError   = "Transaction list length mismatch"
	txMergeMismatch = "Cannot merge transactions: transaction IDs differ"
	txMergeError    = "Cannot merge signatures: %v"
	txNoFilesError  = "No input filenames specified"
	soFlagError     = "-s is not meaningful without -o"
	infoRawTxIssued = "Raw transaction ID %s issued"
	txPoolError     = "Transaction %s kicked out of local node pool: %s"

	infoAutoFeeSet = "Automatically set fee to %d MicroAlgos"

	loggingNotConfigured = "Remote logging is not currently configured and won't be enabled"
	loggingNotEnabled    = "Remote logging is current disabled"
	loggingEnabled       = "Remote logging is enabled.  Node = %s, Guid = %s"

	infoNetworkAlreadyExists = "Network Root Directory '%s' already exists"
	errorCreateNetwork       = "Error creating private network: %s"
	infoNetworkCreated       = "Network %s created under %s"
	errorLoadingNetwork      = "Error loading deployed network: %s"
	errorStartingNetwork     = "Error starting deployed network: %s"
	infoNetworkStarted       = "Network Started under %s"
	infoNetworkStopped       = "Network Stopped under %s"
	infoNetworkDeleted       = "Network Deleted under %s"

	// Wallet
	infoRecoveryPrompt           = "Please type your recovery mnemonic below, and hit return when you are done: "
	infoChoosePasswordPrompt     = "Please choose a password for wallet '%s': "
	infoPasswordConfirmation     = "Please confirm the password: "
	infoCreatingWallet           = "Creating wallet..."
	infoCreatedWallet            = "Created wallet '%s'"
	infoBackupExplanation        = "Your new wallet has a backup phrase that can be used for recovery.\nKeeping this backup phrase safe is extremely important.\nWould you like to see it now? (Y/n): "
	infoPrintedBackupPhrase      = "Your backup phrase is printed below.\nKeep this information safe -- never share it with anyone!"
	infoBackupPhrase             = "\n\x1B[32m%s\033[0m"
	infoNoWallets                = "No wallets found. You can create a wallet with `goal wallet new`"
	errorCouldntCreateWallet     = "Couldn't create wallet: %s"
	errorCouldntInitializeWallet = "Couldn't initialize wallet: %s"
	errorCouldntExportMDK        = "Couldn't export master derivation key: %s"
	errorCouldntMakeMnemonic     = "Couldn't make mnemonic: %s"
	errorCouldntListWallets      = "Couldn't list wallets: %s"
	errorPasswordConfirmation    = "Password confirmation did not match"
	errorBadMnemonic             = "Problem with mnemonic: %s"
	errorBadRecoveredKey         = "Recovered invalid key"
	errorFailedToReadResponse    = "Couldn't read response: %s"
	errorFailedToReadPassword    = "Couldn't read password: %s"

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
)
