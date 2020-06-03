const execFileSync = require('child_process').execFileSync;
var path = require('path');
var cshashExecutable = path.join(__dirname, 'cshash');

module.exports = {
    cshash: function(cert){
        var stdout = execFileSync(cshashExecutable, [cert]);
        return stdout.toString().replace(/\n$/, "");
    },
};
