const { sha256 } = require("js-sha256");
const RIPEMD160 = require('ripemd160')
const { Base58 } = require("../Utils/Base58")
const { verifySignature } = require("../Utils/verifySignature")


module.exports.validate_p2pkh = (prevTrnx, msgHash, transactionData, index) => {
    try {
        let msg = msgHash;
        for (let i = 0; i < transactionData.vin.length; i++) {
            if (i === index) {
                const scriptSig = transactionData.vin[i].scriptsig
                let len = transactionData.vin[i].scriptsig.length
                len = (len / 2).toString(16)
                const prevout = `${len}${scriptSig}`;
                let len2 = prevTrnx.prevout.scriptpubkey.length
                len2 = (len2 / 2).toString(16)
                const prevout2 = `${len2}${prevTrnx.prevout.scriptpubkey}`;
                if (msg.includes(prevout)) {
                    msg = msg.replace(prevout, prevout2)
                }
                continue;
            }
            else {
                const scriptSig = transactionData.vin[i].scriptsig
                let len = transactionData.vin[i].scriptsig.length
                len = (len / 2).toString(16)
                const prevout = `${len}${scriptSig}`;
                if (msg.includes(prevout)) {
                    msg = msg.replace(prevout, "00")
                }
            }
        }
        const hashMessage = Buffer.from(sha256(Buffer.from(sha256(Buffer.from(msg, 'hex')), "hex")), "hex")

        //Extract Address
        const address = prevTrnx.prevout.scriptpubkey_address
        //Extract PKH
        const [, , , PKH, ,] = prevTrnx.prevout.scriptpubkey_asm.split(" ");
        //Validate Address
        const checksum = sha256(Buffer.from(sha256(Buffer.from(`00${PKH}`, 'hex')), "hex")).slice(0, 8)
        const hash = `00${PKH}${checksum}`
        const generatedAddress = Base58(Buffer.from(hash, "hex"))

        if (generatedAddress === address) {
            //Extract signature and publickey
            const [, signature, , publickey] = prevTrnx.scriptsig_asm.split(" ");

            //Performing OP_DUP and OP_HASH160
            const SHA256_PKH_HASH = sha256(Buffer.from(publickey, 'hex'));
            const Generated_PKH = new RIPEMD160().end(Buffer.from(SHA256_PKH_HASH, 'hex')).read().toString('hex');

            //Performing OP_EQUALVERIFY
            if (Generated_PKH === PKH) {
                let verify = verifySignature(signature, publickey, hashMessage)
                return verify
            }
            else {
                return false;
            }
        }
        else {
            return false;
        }
    }
    catch (e) {
        return false;
    }

}