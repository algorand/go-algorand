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
Algorand Node Service has started. Algod executable '%1' using data directory '%2'
.

MessageId=3001
Severity=Informational
SymbolicName=MSG_ALGODSVC_EXIT
Language=English
Algorand Node Service is stopping. Reason: algod executable exited normally.
.

MessageId=3002
Severity=Warning
SymbolicName=MSG_ALGODSVC_TERMINATED
Language=English
Algorand Node Service is stopping. Reason: algod executable terminated abnormally with exit code: %1.
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
Algorand Node Service could not start. The algod executable (%1) failed to start. Win32 error code is %2.
.

MessageId=3005
Severity=Informational
SymbolicName=MSG_ALGODSVC_STOPPED
Language=English
Algorand Node Service has been stopped.
.

; #endif 
