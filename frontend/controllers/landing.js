var elasticClient = require('./../modules/elasticUtil');

exports.get_landing = function(req, res, next){
    res.sendfile("index.html")
}

exports.submit_search = async function(req, res, next){
    console.log("email : ", req.body.search_term)
    result = await elasticClient.searchAll(req.body.search_term)
    console.log(result)
    res.redirect("/")
}
