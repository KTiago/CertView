const { Client } = require('@elastic/elasticsearch')
const config = require('../config/config')
const ObjectsToCsv = require('objects-to-csv')

var client;

module.exports = {
    connect: function(){
        client = new Client({
            node: "http://"+config.production['host']+":"+config.production['port'],
            auth: {
                username: config.production['username'],
                password: config.production['password']
            }
        });
    },
    getClient: function(){
        return client;
    },
    searchAll: async function(index){
        result = await client.search({
            index: index,
            body: {
                query: {
                    "match_all": {}
                }
            },
            size: 1000,
        },{
            ignore: [404],
            maxRetries: 3
        })
        if (result['statusCode'] !== 200){
            return []
        }
        return result['body']['hits']['hits']
    },
    searchHosts: async function(sha1){
        result = await client.search({
            index: "hosts*",
            body: {
                query: {
                    "terms": {
                        "sha1": [sha1]
                    }
                }
            },
            size: 1000,
        },{
            ignore: [404],
            maxRetries: 3
        })
        if (result['statusCode'] !== 200){
            return []
        }
        hits = result['body']['hits']['hits']

        var firstSeen = {};
        var lastSeen = {};
        var ipSet = new Set()
        for (var i = 0; i < hits.length; i++) {
            ip = hits[i]['_source']['ip']
            date = hits[i]['_source']['date']
            if (! ipSet.has(ip)){
                ipSet.add(ip)
                firstSeen[ip] = date
                lastSeen[ip] = date
            }else{
                if (firstSeen[ip] > date){
                    firstSeen[ip] = date
                }
                if (lastSeen[ip] < date){
                    lastSeen[ip] = date
                }
            }
        }
        var hosts = []
        ipSet.forEach(ip => hosts.push({
            "ip" : ip,
            "first_seen" : firstSeen[ip],
            "last_seen" : lastSeen[ip]
        }));
        return hosts
    },
    get: async function(index, id){
        result = await client.get({
            index: index,
            id: id,
        },{
            ignore: [404],
            maxRetries: 3
        })
        if (result['statusCode'] !== 200){
            return null
        }
        return result['body']['_source']
    },
    generateCSV : async function () {
        result = await client.search({
            index: "tags",
            body: {
                query: {
                    "match_all": {}
                }
            },
            size: 1000,
        },{
            ignore: [404],
            maxRetries: 3
        })
        if (result['statusCode'] === 200) {
            var list = []
            hits = result['body']['hits']['hits']
            for (var i = 0; i < hits.length; i++) {
                list.push({
                    tag : hits[i]['_source']['tag'],
                    sha1 : hits[i]['_source']['sha1'],
                    comment : hits[i]['_source']['comment'],
                    date : hits[i]['_source']['date'],
                })
            }
            csv = new ObjectsToCsv(list)
            await csv.toDisk('./public/datasets/analysis.csv')
        }
    }
};
