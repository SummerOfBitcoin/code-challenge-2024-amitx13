const { sha256 } = require("js-sha256");

const hash256 = (input) => {
    return sha256(Buffer.from(sha256(Buffer.from(input, 'hex')), "hex"));
}


const WITNESS_RESERVED_VALUE = Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex',
)

module.exports.coinBaseTransaction = (amt, root) => {
    const ver = "01000000"
    const marker = "00"
    const flag = "01"
    const inCount = "01"
    const txid = "0000000000000000000000000000000000000000000000000000000000000000"
    const vout = "ffffffff"
    const scriptpubkey = "1802d4ce0c486579206974277320406D697450726173616420"
    const sequence = "ffffffff"
    const outCount = "02"
    let value = Buffer.alloc(8);
    let val = amt.toString(16);
    if (val.length % 2 != 0) {
        val = "0" + val;
    }
    let v = Buffer.from(val, "hex").reverse().toString("hex");
    value.write(v, "hex");
    const voutScriptpubkey = "1976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"
    const witnessamount = "0000000000000000";
    const witnessReserved = WITNESS_RESERVED_VALUE.toString('hex')
    const witnessReservedValue = hash256(root + witnessReserved)
    let witnessScriptpubkey = `6a24aa21a9ed${witnessReservedValue}`
    let len = witnessScriptpubkey.length
    len = (len / 2).toString(16)
    let FinalwitnessScriptpubkey = `${len}${witnessScriptpubkey}`
    const stackitems = "01"
    const stackitemssize = "20"
    const witnessItem = "0000000000000000000000000000000000000000000000000000000000000000"
    const locktime = "00000000"
    return ver + marker + flag + inCount + txid + vout + scriptpubkey + sequence + outCount + value.toString("hex") + voutScriptpubkey + witnessamount + FinalwitnessScriptpubkey + stackitems + stackitemssize + witnessItem + locktime
}