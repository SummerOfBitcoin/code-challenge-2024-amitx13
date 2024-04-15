const { sha256 } = require("js-sha256");

const hash256 = (input) => {
    return sha256(Buffer.from(sha256(Buffer.from(input, 'hex')), "hex"));
}

module.exports.generateMerkleRoot = (txids) => {
    if (txids.length === 0) return null

    // reverse the txids
    let allTrxn = txids.map((txid) => Buffer.from(txid, 'hex').reverse().toString('hex'))

    while (allTrxn.length > 1) {
        const hashTrxn = []

        for (let i = 0; i < allTrxn.length; i += 2) {
            let pairTrxn
            if (i + 1 === allTrxn.length) {
                // In case of odd number of elements duplicate the last trxn
                pairTrxn = hash256(allTrxn[i] + allTrxn[i])
            } else {
                pairTrxn = hash256(allTrxn[i] + allTrxn[i + 1])
            }
            hashTrxn.push(pairTrxn)
        }

        allTrxn = hashTrxn
    }

    return allTrxn[0]
}