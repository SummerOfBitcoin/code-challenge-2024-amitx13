const { sha256 } = require("js-sha256");
const RIPEMD160 = require('ripemd160')
const { Base58 } = require("../Utils/Base58")
const { verifySignature } = require("../Utils/verifySignature")
const { encode_compact } = require("../Utils/encode_compact")
const { intToLittleEndianBytes } = require("../Utils/intToLittleEndianBytes.js")


module.exports.validate_p2sh = (prevTrnx, msgHash, transactionData, index) => {
    try {
        let msg;
        const ver = msgHash.slice(0, 8);
        const outLength = encode_compact(transactionData.vout.length)
        let outpointforhashPrevouts = "";
        let outpoint = "";
        let sequenceforhashSequence = "";
        let sequence = "";
        let scriptCode;
        for (let i = 0; i < transactionData.vin.length; i++) {
            let txidforHash;
            let output = intToLittleEndianBytes(transactionData.vin[i].vout);
            let vIndex = output.map(b => b.toString(16).padStart(2, '0')).join('');
            txidforHash = Buffer.from(transactionData.vin[i].txid, "hex").reverse().toString("hex");
            outpointforhashPrevouts += `${txidforHash}${vIndex}`
            sequenceforhashSequence += Buffer.from(transactionData.vin[i].sequence.toString(16), "hex").reverse().toString("hex");
            if (i === index) {
                let txidforHash;
                let output = intToLittleEndianBytes(transactionData.vin[i].vout);
                let vIndex = output.map(b => b.toString(16).padStart(2, '0')).join('');
                txidforHash = Buffer.from(transactionData.vin[i].txid, "hex").reverse().toString("hex");
                outpoint += `${txidforHash}${vIndex}`
                sequence = Buffer.from(prevTrnx.sequence.toString(16), "hex").reverse().toString("hex");
                const [, data] = prevTrnx.scriptsig_asm.split(" ")
                let len = data.length
                len = (len / 2).toString(16)
                const toRemoveHash = `${len}${data}`
                let len2 = toRemoveHash.length
                len2 = (len2 / 2).toString(16)
                const toRemove = `${len2}${toRemoveHash}`
                msgHash = msgHash.replace(toRemove, "")
            }

        }
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
        const address = prevTrnx.prevout.scriptpubkey_address;
        const [, , PKH,] = prevTrnx.prevout.scriptpubkey_asm.split(" ");
        const checksum = sha256(Buffer.from(sha256(Buffer.from(`05${PKH}`, 'hex')), "hex")).slice(0, 8)
        const hash = `05${PKH}${checksum}`
        const generatedAddress = Base58(Buffer.from(hash, "hex"))
        if (generatedAddress === address) {
            if (prevTrnx.scriptsig.length > 288) {
                let scriptArray = prevTrnx.scriptsig_asm.split(" ");
                let signatures = [];
                let publicKeys;
                for (let i = 0; i < scriptArray.length; i++) {
                    if (scriptArray[i] === "OP_PUSHBYTES_72" || scriptArray[i] === "OP_PUSHBYTES_71") {
                        if (scriptArray[i + 1].slice(0, 2) === "30") {
                            signatures.push(scriptArray[i + 1]);
                        } else {
                            let str = scriptArray[i + 1].slice(2)
                            publicKeys = str.match(/.{68}/g);
                        }
                    }
                }
                let len = scriptArray[scriptArray.length - 1].length
                len = (len / 2).toString(16)
                scriptCode = `${len}${scriptArray[scriptArray.length - 1]}`
                msg = ver + hashPrevouts + hashSequence + outpoint + scriptCode + inAmt.toString("hex") + sequence + hashOutputs + HashTypenLockTime
                const hashMessage = Buffer.from(sha256(Buffer.from(sha256(Buffer.from(msg, 'hex')), "hex")), "hex")
                for (let i = 0; i < signatures.length; i++) {
                    for (let j = 0; j < publicKeys.length; j++) {
                        let publicKey = publicKeys[j].slice(2);
                        //code modification needed
                        let result = verifySignature(signatures[i], publicKey, hashMessage)
                        if (result) {
                            return result;
                        }
                    }
                }

            } else {
                const [, reedemscript] = prevTrnx.scriptsig_asm.split(" ");
                const SHA256_PKH_HASH = sha256(Buffer.from(reedemscript, 'hex'));
                const Generated_PKH = new RIPEMD160().end(Buffer.from(SHA256_PKH_HASH, 'hex')).read().toString('hex');
                if (prevTrnx.witness.length >= 3) {
                    let len = prevTrnx.witness[prevTrnx.witness.length - 1].length
                    len = (len / 2).toString(16)
                    scriptCode = `${len}${prevTrnx.witness[prevTrnx.witness.length - 1]}`
                } else {
                    scriptCode = `1976a914${reedemscript.slice(4)}88ac`
                }
                if (Generated_PKH === PKH) {
                    //Performing OP_CHECKSIG
                    msg = ver + hashPrevouts + hashSequence + outpoint + scriptCode + inAmt.toString("hex") + sequence + hashOutputs + HashTypenLockTime
                    const hashMessage = Buffer.from(sha256(Buffer.from(sha256(Buffer.from(msg, 'hex')), "hex")), "hex")
                    if (prevTrnx.witness.length >= 3) {
                        let str = prevTrnx.witness[prevTrnx.witness.length - 1].slice(2)
                        let publicKeys = str.match(/.{68}/g);
                        for (let i = 1; i < prevTrnx.witness.length - 1; i++) {
                            let signature = prevTrnx.witness[i]
                            for (let j = 0; j < publicKeys.length; j++) {
                                let publicKey = publicKeys[i].slice(2);
                                let result = verifySignature(signature, publicKey, hashMessage)
                                if (result) {
                                    return result;
                                }
                            }
                        }
                    }
                    else {
                        const signature = prevTrnx.witness[0]
                        const publicKey = prevTrnx.witness[1]
                        let result = verifySignature(signature, publicKey, hashMessage)
                        return result
                    }

                }
                else {
                    return false
                }
            }
        }
        else {
            return false
        }
    } catch (e) {
        return false
    }
}