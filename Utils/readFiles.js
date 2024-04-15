const fs = require("fs");

module.exports.readMempool = () => {
    return fs.readdirSync("./mempool");
}

