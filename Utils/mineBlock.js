const { sha256 } = require("js-sha256");
const { intToLittleEndianBytes } = require("./intToLittleEndianBytes")
module.exports.mineBlock = (merkleRoot) => {
    let blockHeaderHex = "";
    const version = 0x00000004;
    const prevBlock = "0000000000000000000000000000000000000000000000000000000000000000"
    const time = Math.floor(new Date().getTime() / 1000);
    const bits = "1f00ffff";
    let nonce = 1;
    while (true) {
        const blockHeader = {
            version,
            prevBlock,
            merkleRoot,
            time,
            bits,
            nonce,
        };
        const blockHash = sha256(sha256(JSON.stringify(blockHeader)));
        let valid = true;
        for (let i = 0; i < bits.length; i++) {
            if (parseInt(blockHash[i], 16) > parseInt(bits[i], 16)) {
                valid = false;
                break;
            } else if (parseInt(blockHash[i], 16) < parseInt(bits[i], 16)) {
                break;
            }
        }
        if (valid) {
            const out = intToLittleEndianBytes(nonce)
            const finalNonce = out.map(b => b.toString(16).padStart(2, '0')).join('');
            blockHeaderHex = intToLittleEndianBytes(version).map(b => b.toString(16).padStart(2, '0')).join('')+prevBlock+merkleRoot+Buffer.from(time.toString(16), "hex").reverse().toString("hex")+Buffer.from(bits, "hex").reverse().toString("hex")+finalNonce
            return blockHeaderHex;
        }
        nonce++;
    }
}