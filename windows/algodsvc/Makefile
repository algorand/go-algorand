#
# Algodsvc Makefile.
# (C) 2021 Randlabs.
#

SC=sc
RC=windres
MC=windmc
REG=reg
SERVICENAME=AlgodSvc
SERVICEDISPLAYNAME="Algorand Node Windows Service" 
CC=g++
CFLAGS=-Wall -static -pedantic -O2 -g -fanalyzer -DFORTIFY_SOURCE=2 -fstack-protector
LDFLAGS=-municode
OUTNAME=algodsvc
TARGET=$(OUTNAME).exe
RCOUT=$(OUTNAME).rc
RESOUT=$(OUTNAME)_res.o
HDROUT=$(OUTNAME).h
MSGBIN=MSG00001.BIN
SOURCES=algodsvc.cpp

all: $(RCOUT) $(HDROUT) $(MSGBIN) $(RESOUT) $(TARGET)

$(RCOUT) $(HDROUT) $(MSGBIN): $(OUTNAME).mc
	$(MC) .\$(OUTNAME).mc

$(RESOUT): $(OUTNAME).rc
	$(RC) -i .\$(OUTNAME).rc -o $(RESOUT)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) $(RESOUT) $(LDFLAGS) -o $(TARGET)

.PHONY: clean install uninstall

clean:
	@rm -f $(TARGET)
	@rm -f $(RCOUT)
	@rm -f $(RESOUT)
	@rm -f $(HDROUT)
	@rm -f $(MSGBIN)

install:
	$(SC) create $(SERVICENAME)_$(NETWORK) binPath= "$(SVCEXE) $(NETWORK) \"$(ALGODEXE)\" \"$(NODEDATADIR)\"" DisplayName= $(SERVICEDISPLAYNAME) obj= "NT AUTHORITY\NetworkService"
	$(REG) add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Algorand Node Service" /v EventMessageFile /d $(SVCEXE)

uninstall:
	$(SC) delete $(SERVICENAME)_$(NETWORK)

