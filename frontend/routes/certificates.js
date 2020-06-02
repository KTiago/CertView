var express = require('express');
var elastic = require('../modules/elasticUtil')
var router = express.Router();

router.get('/', async function(req, res, next) {
  var sha1 = req.query.sha1
  if (sha1 === undefined){
    res.render('certificates')
  } else if(sha1.length != 40){
    res.status(404)
    res.render('certificate_not_found')
  }else{
    var certificate = await elastic.get("certificates", sha1)
    var hosts = await elastic.searchHosts(sha1)
    if (certificate === null){
      res.status(404)
      res.render('certificate_not_found')
    }else{
      res.render('certificate', {
        certificate: certificate,
        hosts : hosts
      });
    }
  }
});

module.exports = router;
