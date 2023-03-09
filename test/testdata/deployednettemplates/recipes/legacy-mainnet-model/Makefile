all:	network_performance_rules

network_performance_rules:	generate_network_rules.js data/bandwidth.json data/countries.json data/latency.json configs/node.json configs/nonPartNode.json configs/relay.json network-tpl.json
	node generate_network_rules.js
	../../generate-recipe/generate_network.py --template ./network-tpl.json

clean:
	rm -f network_performance_rules
