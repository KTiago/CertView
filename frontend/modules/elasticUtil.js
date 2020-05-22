const { Client } = require('@elastic/elasticsearch')
const url = "http://localhost:9200"
var client;

module.exports = {
    connect: function(){
        console.log("Creating ElasticSearch client")
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
            }
        },{
            ignore: [404],
            maxRetries: 3
        })
        if (result['body']['statusCode'] !== 200){
            return null
        }
        return result['body']['hits']['hits']
    }
};
