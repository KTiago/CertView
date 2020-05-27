const { Client } = require('@elastic/elasticsearch')
const url = "http://localhost:9200"
var client;

module.exports = {
    connect: function(){
        client = new Client({ node: url });
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
