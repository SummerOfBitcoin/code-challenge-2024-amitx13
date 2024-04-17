const { encode_compact } = require("../Utils/encode_compact")
const { intToLittleEndianBytes } = require("../Utils/intToLittleEndianBytes")

module.exports.calculateMessageHash = (trnx) => {
    if (trnx) {
        const ver = intToLittleEndianBytes(trnx.version);
        const version = ver.map(b => b.toString(16).padStart(2, '0')).join('');
        const ltime = intToLittleEndianBytes(trnx.locktime);
        const locktime = ltime.map(b => b.toString(16).padStart(2, '0')).join('');
        const inLength = encode_compact(trnx.vin.length)
        const outLength = encode_compact(trnx.vout.length)
        let sigHash = Buffer.alloc(4);
        let msgHash = `${version}${inLength}`;

        for (const prevTrnx of trnx.vin) {
            const rTxid = Buffer.from(prevTrnx.txid, 'hex').reverse().toString('hex');
            const output = intToLittleEndianBytes(prevTrnx.vout); //convert to 4byte little ending
            const index = output.map(b => b.toString(16).padStart(2, '0')).join('');
            const seq = intToLittleEndianBytes(prevTrnx.sequence)
            const sequence = seq.map(b => b.toString(16).padStart(2, '0')).join('');

            if (prevTrnx.prevout.scriptpubkey_type === "p2pkh") {
                const [, signature, ,] = prevTrnx.scriptsig_asm.split(" ")
                sigHash.writeInt32LE(signature.substr(-2), 0); //convert to 4byte little ending
                const scriptSig = prevTrnx.scriptsig
                let len = prevTrnx.scriptsig.length
                len = (len / 2).toString(16)
                const prevout = `${len}${scriptSig}`;
                msgHash += `${rTxid}${index}${prevout}${sequence}`
            }

            if (prevTrnx.prevout.scriptpubkey_type === "p2sh") {
                let signature;
                if (prevTrnx.witness) {
                    if (prevTrnx.witness.length > 2) {
                        signature = prevTrnx.witness[1];
                    }
                    else {
                        signature = prevTrnx.witness[0];
                    }
                    sigHash.writeInt32LE(signature.substr(-2), 0);
                    const Script = prevTrnx.scriptsig;
                    let len = prevTrnx.scriptsig.length
                    len = (len / 2).toString(16)
                    const redeemScript = `${len}${Script}`;
                    msgHash += `${rTxid}${index}${redeemScript}${sequence}`
                }
                if (prevTrnx.scriptsig.length > 288) {
                    const Script = prevTrnx.scriptsig;
                    let len = prevTrnx.scriptsig.length
                    len = (len / 2).toString(16)
                    const redeemScript = `${len}${Script}`;
                    msgHash += `${rTxid}${index}${redeemScript}${sequence}`
                }
            }

            if (prevTrnx.prevout.scriptpubkey_type === "v0_p2wpkh") {
                const signature = prevTrnx.witness[0]
                sigHash.writeInt32LE(signature.substr(-2), 0);
                msgHash += `${rTxid}${index}${`00`}${sequence}`
            }
            if (prevTrnx.prevout.scriptpubkey_type === "v0_p2wsh") {
                const signature = prevTrnx.witness[1]
                sigHash.writeInt32LE(signature.substr(-2), 0);
                msgHash += `${rTxid}${index}00${sequence}`
            }
            if (prevTrnx.prevout.scriptpubkey_type === "v1_p2tr") {
                msgHash += `${rTxid}${index}${`00`}${sequence}`
            }
        }

        msgHash += `${outLength}`;
        for (const vTrnx of trnx.vout) {
            let value = Buffer.alloc(8);
            let vout = vTrnx.value.toString(16);
            if (vout.length % 2 != 0) {
                vout = "0" + vout;
            }
            let v = Buffer.from(vout, "hex").reverse().toString("hex");
            value.write(v, "hex");
            let len = vTrnx.scriptpubkey.length
            len = (len / 2).toString(16)
            const scriptpubkey = `${len}${vTrnx.scriptpubkey}`;
            msgHash += `${value.toString("hex")}${scriptpubkey}`
        }
        msgHash += `${locktime.toString("hex")}${sigHash.toString('hex')}`

        return msgHash;
    }
}