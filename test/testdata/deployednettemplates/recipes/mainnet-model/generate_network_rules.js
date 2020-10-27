const fs = require('fs');

const RELAY_BANDWIDTH = 1000
const SAME_REGION_RELAY_TO_RELAY_LATENCY = 10
const CROSS_REGION_NODE_BANDWIDTH_FACTOR = 0.8

const countries = JSON.parse(fs.readFileSync('./data/countries.json'))
const countryBandwidths = JSON.parse(fs.readFileSync('./data/bandwidth.json'))
const latencies = JSON.parse(fs.readFileSync('./data/latency.json'))

const continentToGroup = {
    "North America": "us",
    "Europe": "eu",
    "Asia Pacific": "ap",
    "Africa": "af",
    "Australia": "au",
}

var latencyMap = []
var countryToContinent = []
var continentBandwidths = []

latencies.forEach((latency) => {
    if (!latencyMap[latency.source]) {
        latencyMap[latency.source] = []
    }
    latencyMap[latency.source][latency.target] = latency.latency
})

countries.forEach((country) => {
    countryToContinent[country.country] = country.continent
})

countryBandwidths.forEach((countryBandwidth) => {
    const continent = countryToContinent[countryBandwidth[0]]
    if (!continent) {
        console.log(countryBandwidth)
    }
    if(Object.keys(continentBandwidths).indexOf(continent) == -1) {
        continentBandwidths[continent] = {
            bandwidths: []
        }
        
    }
    continentBandwidths[continent].bandwidths.push(countryBandwidth[1])
})

const average = (data) => {
    var sum = data.reduce(function(sum, value){
      return sum + value;
    }, 0);
    return sum / data.length
}

var writer = fs.createWriteStream('./network_performance_rules', {
    flags: 'w'
})

Object.keys(continentToGroup).forEach((source) => {
    Object.keys(continentToGroup).forEach((target) => {
        sourceGroup = continentToGroup[source]
        targetGroup = continentToGroup[target]
        const bandwidth = average(continentBandwidths[source]['bandwidths'])
        const latency = latencyMap[source][target]
        var relay_to_relay_latency
        var node_bandwidth_factor
        if (sourceGroup==targetGroup) {
            relay_to_relay_latency = SAME_REGION_RELAY_TO_RELAY_LATENCY
            node_bandwidth_factor = 1.0
        } else {
            relay_to_relay_latency = latency
            node_bandwidth_factor = CROSS_REGION_NODE_BANDWIDTH_FACTOR
        }
        writer.write(`${sourceGroup}-n ${targetGroup}-r ${Math.round(bandwidth*node_bandwidth_factor)} ${Math.round(latency)}\n`)
        writer.write(`${sourceGroup}-r ${targetGroup}-n ${RELAY_BANDWIDTH} ${Math.round(latency)}\n`)
        writer.write(`${sourceGroup}-r ${targetGroup}-r ${RELAY_BANDWIDTH} ${Math.round(relay_to_relay_latency)}\n`)
    })
})

writer.end()
