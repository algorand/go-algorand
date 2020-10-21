const fs = require('fs');

const RELAY_BANDWIDTH = 1000

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
        writer.write(`${sourceGroup}-n ${targetGroup}-r ${Math.round(bandwidth)} ${Math.round(latency)}\n`)
        writer.write(`${sourceGroup}-r ${targetGroup}-n ${RELAY_BANDWIDTH} ${Math.round(latency)}\n`)
        writer.write(`${sourceGroup}-r ${targetGroup}-r ${RELAY_BANDWIDTH} ${Math.round(latency)}\n`)
    })
})

writer.end()
