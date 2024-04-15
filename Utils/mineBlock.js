const { sha256 } = require("js-sha256");
const { intToLittleEndianBytes } = require("./intToLittleEndianBytes")

const hash256 = (input) => {
    return sha256(Buffer.from(sha256(Buffer.from(input, 'hex')), "hex"));
}


module.exports.mineBlock = (merkleRoot) => {
    const version = intToLittleEndianBytes(0x00000004).map(b => b.toString(16).padStart(2, '0')).join('');
    const prevBlock = "0000000000000000000000000000000000000000000000000000000000000000"
    const time = Math.floor(new Date().getTime() / 1000);
    const target = Buffer.from('00000ffff0000000000000000000000000000000000000000000000000000000', 'hex')
    const bits = "ffff001f";
    let nonce = 1;
    while (true) {
        const out = intToLittleEndianBytes(nonce)
        const finalNonce = out.map(b => b.toString(16).padStart(2, '0')).join('');
        const blockHeader = version + prevBlock + merkleRoot + Buffer.from(time.toString(16), "hex").reverse().toString("hex") + bits + finalNonce
        const blockHash = Buffer.from(hash256(blockHeader), "hex").reverse()
        if (target.compare(blockHash) > 0) {
            return blockHeader; // Return block header buffer as hex string
        }
        nonce++;
    }
}