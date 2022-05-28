NETWORKS = $${HOME}/networks
NAME = niftynetwork
TEMP_NETWORK = $(NETWORKS)/$(NAME)
GO_ALGORAND = ../../..
NODE_TEMPLATE = $(GO_ALGORAND)/test/testdata/nettemplates/OneNodeFuture.json
ALGORAND_DATA = $(TEMP_NETWORK)/Primary
STATUS = 

# foo:
# ifeq ($(strip $(STATUS)), running)
# 	echo 
# else
# 	echo $(STATUS)
# endif

echo:
	echo NETWORKS: $(NETWORKS)
	echo NAME: $(NAME)
	echo TEMP_NETWORK: $(TEMP_NETWORK)
	echo GO_ALGORAND: $(GO_ALGORAND)
	echo NODE_TEMPLATE: $(NODE_TEMPLATE)
	echo ALGORAND_DATA: $(ALGORAND_DATA)
	echo FUNDER: $(FUNDER)
	echo STATUS: $(STATUS)

# node
create_and_start: create start status 
	make sleep

stop_and_nuke: stop nuke

create:
	mkdir -p $(NETWORKS)
	goal network create -n $(NAME) -r $(TEMP_NETWORK) -t $(NODE_TEMPLATE)

start:
	goal node start  -d $(ALGORAND_DATA)

stop:
	goal node stop  -d $(ALGORAND_DATA)

nuke:
	rm -rf $(TEMP_NETWORK)

round:
	goal node lastround -d $(ALGORAND_DATA)

status:
	goal node status -d $(ALGORAND_DATA)
	# STATUS =running
	# make echo


committed:
	goal node status -d $(ALGORAND_DATA) | egrep "committed|Round"

# account
list:
	goal account list -d $(ALGORAND_DATA)

funder:
	make list | awk '{print $$2}'

# misc
SLEEPTIME = 5
sleep:
	sleep $(SLEEPTIME)
