const { encode_compact } = require("../Utils/encode_compact")
const { intToLittleEndianBytes } = require("../Utils/intToLittleEndianBytes")



module.exports.calculateTransactionHex = (trnx) => {
    if (trnx) {
        const ver = intToLittleEndianBytes(trnx.version);
        const version = ver.map(b => b.toString(16).padStart(2, '0')).join('');
        const ltime = intToLittleEndianBytes(trnx.locktime);
        const locktime = ltime.map(b => b.toString(16).padStart(2, '0')).join('');

        const inLength = encode_compact(trnx.vin.length)
        const outLength = encode_compact(trnx.vout.length)
        const witnessExist = trnx.vin.map((script) => {
            if (script.prevout.scriptpubkey_type === "p2sh") {

                return true;
            }
            if (script.prevout.scriptpubkey_type === "v0_p2wpkh") {
                return true;
            }
            if (script.prevout.scriptpubkey_type === "v0_p2wsh") {
                return true;
            }
            if (script.prevout.scriptpubkey_type === "v1_p2tr") {
                return true;
            }
        })
        let msgHash;
        if (witnessExist) {
            msgHash = `${version}0001${inLength}`;
        }
        else {
            msgHash = `${version}${inLength}`;
        }

        for (const prevTrnx of trnx.vin) {
            const rTxid = Buffer.from(prevTrnx.txid, 'hex').reverse().toString('hex');
            const output = intToLittleEndianBytes(prevTrnx.vout); //convert to 4byte little ending
            const index = output.map(b => b.toString(16).padStart(2, '0')).join('');
            //const sequence = Buffer.from(prevTrnx.sequence.toString(16), "hex").reverse().toString("hex"); //convert to hex
            const seq = intToLittleEndianBytes(prevTrnx.sequence)
            const sequence = seq.map(b => b.toString(16).padStart(2, '0')).join('');

            if (prevTrnx.prevout.scriptpubkey_type === "p2pkh") {
                const scriptSig = prevTrnx.scriptsig
                let len = prevTrnx.scriptsig.length
                len = (len / 2).toString(16)
                const prevout = `${len}${scriptSig}`;
                msgHash += `${rTxid}${index}${prevout}${sequence}`
            }
            if (prevTrnx.prevout.scriptpubkey_type === "p2sh") {
                if (prevTrnx.witness) {
                    const Script = prevTrnx.scriptsig;
                    let len = prevTrnx.scriptsig.length
                    len = (len / 2).toString(16)
                    const redeemScript = `${len}${Script}`;
                    msgHash += `${rTxid}${index}${redeemScript}${sequence}`
                }
            }
            if (prevTrnx.prevout.scriptpubkey_type === "v0_p2wpkh") {
                msgHash += `${rTxid}${index}${`00`}${sequence}`
            }
            if (prevTrnx.prevout.scriptpubkey_type === "v0_p2wsh") {
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
        if (witnessExist) {
            trnx.vin.map((data) => {
                if (data.witness) {
                    let tlength = encode_compact(data.witness.length)
                    msgHash += `${tlength}`
                    data.witness.forEach((wData) => {
                        let len = wData.length
                        len = (len / 2).toString(16)
                        msgHash += `${len}${wData}`;
                    })
                }
            })
            msgHash += `${locktime.toString("hex")}`
        }
        else {
            msgHash += `${locktime.toString("hex")}`
        }

        return msgHash;

    }
}