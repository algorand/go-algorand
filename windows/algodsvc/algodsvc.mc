; //
; // Algodsvc Message File
; // (c)2021 Rand Labs.
; //
; #ifndef __ALGOSVC_MC_H__
; #define __ALGOSVC_MC_H__

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )

MessageIdTypedef=DWORD

MessageId=3000
Severity=Informational
SymbolicName=MSG_ALGODSVC_STARTED
Language=English
Algorand Node Service has started for network %1. Algod executable '%2' using data directory '%3'
.

MessageId=3001
Severity=Informational
SymbolicName=MSG_ALGODSVC_EXIT
Language=English
Algorand Node Service is stopping for network '%1'. Reason: algod executable exited normally.
.

MessageId=3002
Severity=Warning
SymbolicName=MSG_ALGODSVC_TERMINATED
Language=English
Algorand Node Service is stopping for network '%1'. Reason: algod executable terminated abnormally with exit code: %2.
.

MessageId=3003
Severity=Error
SymbolicName=MSG_ALGODSVC_CONFIGERROR
Language=English
Algorand Node Service could not start. Required configuration registry entries not found.
.

MessageId=3004
Severity=Error
SymbolicName=MSG_ALGODSVC_CREATEPROCESS
Language=English
Algorand Node Service could not start for network '%1'. Reason: The algod executable '%2' failed to start. CreateProcess Win32 error code is %3.
.

MessageId=3005
Severity=Informational
SymbolicName=MSG_ALGODSVC_STOPPED
Language=English
Algorand Node Service for network '%1' has been stopped.
.

MessageId=3006
Severity=Error
SymbolicName=MSG_ALGODSVC_ARGCOUNTERROR
Language=English
Algorand Node Service could not start. Invalid number of arguments at ServiceMain entry point.
.

MessageId=3007
Severity=Error
SymbolicName=MSG_ALGODSVC_INVALIDNETWORK
Language=English
Algorand Node Service could not start. Invalid network parameter (%1) must be testnet, mainnet or betanet.
.

MessageId=3007
Severity=Error
SymbolicName=MSG_ALGODSVC_INVALIDNODEDATADIR
Language=English
Algorand Node Service could not start. Invalid, non existent or non-accesible node data directory specified (%1).
.

MessageId=3008
Severity=Informational
SymbolicName=MSG_ALGODSVC_PREFLIGHTCONFIGDATA
Language=English
Algorand Node Service for network '%1'. Pre-flight configuration: algod.exe='%2' Node Data Directory='%3'
.


; #endif 
