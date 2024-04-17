const { verifySignature } = require("../Utils/verifySignature")
const { BitcoinAddress } = require('bech32-buffer');
const { sha256 } = require("js-sha256");
const { intToLittleEndianBytes } = require("../Utils/intToLittleEndianBytes.js")
const { encode_compact } = require("../Utils/encode_compact")

module.exports.validate_p2wsh = (prevTrnx, msgHash, transactionData, index) => {
    try {
        let msg;
        const ver = msgHash.slice(0, 8)
        const outLength = encode_compact(transactionData.vout.length)
        let outpointforhashPrevouts = "";
        let outpointTxid = Buffer.from(prevTrnx.txid, "hex").reverse().toString("hex");
        const out = intToLittleEndianBytes(prevTrnx.vout); //convert to 4byte little ending
        const outIndex = out.map(b => b.toString(16).padStart(2, '0')).join('');
        let sequenceforhashSequence = "";
        let sequence = Buffer.from(prevTrnx.sequence.toString(16), "hex").reverse().toString("hex");
        let scriptCode;
        for (let i = 0; i < transactionData.vin.length; i++) {
            let txidforHash;
            let indexforHash;
            txidforHash = Buffer.from(transactionData.vin[i].txid, "hex").reverse().toString("hex");
            const output = intToLittleEndianBytes(transactionData.vin[i].vout); //convert to 4byte little ending
            indexforHash = output.map(b => b.toString(16).padStart(2, '0')).join('');
            outpointforhashPrevouts += `${txidforHash}${indexforHash}`
            sequenceforhashSequence += Buffer.from(transactionData.vin[i].sequence.toString(16), "hex").reverse().toString("hex");
        }

        let len = prevTrnx.witness[prevTrnx.witness.length - 1].length
        len = (len / 2).toString(16)
        scriptCode = `${len}${prevTrnx.witness[prevTrnx.witness.length - 1]}`
        let inAmt = Buffer.alloc(8);
        let vout = prevTrnx.prevout.value.toString(16);
        if (vout.length % 2 != 0) {
            vout = "0" + vout;
        }
        let v = Buffer.from(vout, "hex").reverse().toString("hex");
        inAmt.write(v, "hex");
        const output = msgHash.split(sequenceforhashSequence.slice(-8) + outLength.toString("hex"))[1].slice(0, -16)
        const hashPrevouts = sha256(Buffer.from(sha256(Buffer.from(outpointforhashPrevouts, 'hex')), "hex"));
        const hashSequence = sha256(Buffer.from(sha256(Buffer.from(sequenceforhashSequence, 'hex')), "hex"));
        const hashOutputs = sha256(Buffer.from(sha256(Buffer.from(output, 'hex')), "hex"));
        const HashTypenLockTime = msgHash.slice(-16);

        msg = ver + hashPrevouts + hashSequence + outpointTxid + outIndex.toString("hex") + scriptCode + inAmt.toString("hex") + sequence + hashOutputs + HashTypenLockTime
        const hashMessage = Buffer.from(sha256(Buffer.from(sha256(Buffer.from(msg, 'hex')), "hex")), "hex")
        const address = prevTrnx.prevout.scriptpubkey_address;
        const [, , PKH] = prevTrnx.prevout.scriptpubkey_asm.split(" ");
        const genAddress = new BitcoinAddress('bc', 0, Buffer.from(PKH, 'hex'));
        const encodedAddress = genAddress.encode();
        if (address === encodedAddress) {
            let strArr = prevTrnx.inner_witnessscript_asm.split(" ")
            let publicKeys = [];
            strArr.forEach((Op_code, index) => {
                if (Op_code === 'OP_PUSHBYTES_33') {
                    publicKeys.push(strArr[index + 1])
                }
            })
            let verify = false;
            for (let i = 1; i < prevTrnx.witness.length - 1; i++) {
                let signature = prevTrnx.witness[i]
                for (let j = 0; j < publicKeys.length; j++) {
                    let publicKey = publicKeys[j]
                    let result = verifySignature(signature, publicKey, hashMessage)
                    if (result) {
                        return result;
                    }
                }
            }
            return verify;
        } else {
            return false
        }
    } catch (e) {
        return false
    }
}