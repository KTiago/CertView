var express = require('express');
var elastic = require('../modules/elasticUtil')
var router = express.Router();

router.get('/:sha1', async function(req, res, next) {
  var sha1 = req.params.sha1
  var result = await elastic.get("certificates", sha1)
  if (result === null){
    res.status(404)
        .send('Not found');
  }else{
    res.send(result);
  }
});

module.exports = router;
