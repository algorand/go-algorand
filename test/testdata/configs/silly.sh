export GGG="http://lol.com:333/you"
jq --arg MINE $GGG '. + {"GossipFanout": $MINE}' ./config-v22.json > me.json
