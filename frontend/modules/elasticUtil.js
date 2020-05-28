const { Client } = require('@elastic/elasticsearch')
const config = require('../config/config')
var client;

module.exports = {
    connect: function(){
        client = new Client({
            node: "http://"+config.development['host']+":"+config.development['port'],
            auth: {
                username: config.development['username'],
                password: config.development['password']
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
            return null
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
            return null
        }
        return result['body']['_source']
    }
};
