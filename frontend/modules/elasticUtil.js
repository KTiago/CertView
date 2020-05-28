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
    get: async function(index, id){
        result = await client.get({
            index: index,
            id: id,
        },{
            ignore: [404],
            maxRetries: 3
        })
        if (result['statusCode'] !== 200){
            return []
        }
        return result['body']['_source']
    },
    generateCSV : async function () {
        result = await client.search({
            index: "icedid", // replace by "tags"
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
                    ip : hits[i]['_source']['ip'],
                    sha1 : hits[i]['_source']['sha1'],
                })
            }
            console.log(list)
            csv = new ObjectsToCsv(list)
            await csv.toDisk('./public/datasets/analysis.csv')
        }
    }
};
