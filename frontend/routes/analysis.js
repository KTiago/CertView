var express = require('express');
var elastic = require('../modules/elasticUtil')
var router = express.Router();

router.get('/', async function(req, res, next) {
  var data = await elastic.searchAll("tags")
  console.log(data)
  res.render('analysis',{data : data});
});

module.exports = router;
