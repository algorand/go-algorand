#
# Algodsvc Makefile.
# (C) 2021 Randlabs.
#

SC=sc
REG=reg
SERVICENAME=AlgodSvc
SERVICEDISPLAYNAME="Algorand Node Windows Service" 
CC=gcc
CFLAGS=-Wall -pedantic -O2 -g -fanalyzer -DFORTIFY_SOURCE=2 -fstack-protector
LDFLAGS=
TARGET=algodsvc.exe
SOURCES=algodsvc.cpp

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(TARGET)

.PHONY: clean install uninstall

clean:
	@rm -f $(TARGET)

install:
	$(SC) create $(SERVICENAME) binPath= "$(SVCEXE)" DisplayName= $(SERVICEDISPLAYNAME)
	$(REG) add HKLM\SYSTEM\CurrentControlSet\Services\$(SERVICENAME)\Parameters /v NodeDataDirectory /t REG_SZ /d $(NODEDATADIR)
	$(REG) add HKLM\SYSTEM\CurrentControlSet\Services\$(SERVICENAME)\Parameters /v AlgodExeFileName /t REG_SZ /d $(ALGODEXE)

uninstall:
	$(SC) delete $(SERVICENAME)

