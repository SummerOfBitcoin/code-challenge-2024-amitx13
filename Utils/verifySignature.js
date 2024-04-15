const { decode } = require("../Utils/decodeSignature")
const { fromDER } = require("../Utils/decodeSignature")
const secp256k1 = require('secp256k1')


module.exports.verifySignature = (signature, publicKey, hashMessage) => {
    const signatureBuffer = Buffer.from(signature, 'hex').slice(0, -1);
    const obj = decode(signatureBuffer)
    const r = fromDER(obj.r);
    const s = fromDER(obj.s);
    const Fsignature = Buffer.concat([r, s], 64)
    const signatureUint8Array = new Uint8Array(Fsignature);
    const publickeyBuffer = Buffer.from(publicKey, 'hex');
    const publickeyUint8Array = new Uint8Array(publickeyBuffer);
    const verify = secp256k1.ecdsaVerify(signatureUint8Array, hashMessage, publickeyUint8Array)
    return verify
}
