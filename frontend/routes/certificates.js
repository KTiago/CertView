var express = require('express');
var elastic = require('../modules/elasticUtil')
var router = express.Router();
var cshashUtil = require('../modules/cshashUtil');
const { Certificate } = require('@fidm/x509')

router.get('/', async function (req, res, next) {
    var sha1 = req.query.sha1
    if (sha1 === undefined) {
        res.render('certificates')
    } else {
      sha1 = sha1.trim() // trim whitespace for convenience when use copy paste.
        if (sha1.length != 40) {
            res.status(404)
            res.render('certificate_not_found')
        } else {
            var certificate = await elastic.get("certificates", sha1)
            var hosts = await elastic.searchHosts(sha1)
            if (certificate === null) {
                res.status(404)
                res.render('certificate_not_found')
            } else {
                cshash = cshashUtil.cshash(certificate['raw'])
                var certPem = "-----BEGIN CERTIFICATE-----\n" + certificate['raw'] + "\n-----END CERTIFICATE-----"
                const parsed = Certificate.fromPEM(Buffer.from(certPem, 'utf8'))
                res.render('certificate', {
                    certificate: certificate,
                    parsed: parsed,
                    hosts: hosts,
                    cshash: cshash,
                });
            }
        }
    }
});

module.exports = router;
