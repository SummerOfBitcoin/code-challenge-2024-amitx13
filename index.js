const fs = require("fs");
const { sha256 } = require("js-sha256");
const { readMempool } = require("./Utils/readFiles")
const { validate_p2pkh } = require("./Script/validate_p2pkh")
const { validate_p2sh } = require("./Script/validate_p2sh")
const { validate_p2wpkh } = require("./Script/validate_p2wpkh")
const { validate_p2wsh } = require("./Script/validate_p2wsh")
const { calculateMessageHash } = require("./Utils/calculateMessageHash")
const { mineBlock } = require("./Utils/mineBlock")
const { generateMerkleRoot } = require("./Utils/generateMerkleRoot")
const { coinBaseTransaction } = require("./Utils/coinBaseTransaction")

function main() {

    const mempoolFiles = readMempool();
    const transactions = [];
    let amt = 650000000;
    let merkleRoot = "";
    mempoolFiles.forEach((file) => {
        const transactionData = JSON.parse(
            fs.readFileSync(`./mempool/${file}`, "utf-8"),
        );
        let verify = true;
        let input_value = 0;
        let output_value = 0;
        const maxLength = Math.max(transactionData.vin.length, transactionData.vout.length);

        for (let i = 0; i < maxLength; i++) {
            if (i < transactionData.vin.length) {
                input_value += transactionData.vin[i].prevout.value;
                if (transactionData.vin[i].sequence < 4294967293) {
                    if (transactionData.vin[i].sequence === 0) {
                        verify = true;
                        continue;
                    }
                    else {
                        verify = false;
                        break;
                    }
                }
            }
            if (i < transactionData.vout.length) {
                output_value += transactionData.vout[i].value;
                if (transactionData.vout[i].scriptpubkey_type === "op_return") {
                    verify = false;
                    break;
                }
            }
            if (maxLength > 2) {
                verify = false;
                break;
            }
        }
        if (verify && input_value > output_value) {
            let isVerify = false;
            const msgHash = calculateMessageHash(transactionData);
            for (const [index, prevTrnx] of transactionData.vin.entries()) {
                if (prevTrnx.prevout.scriptpubkey_type === "p2pkh") {
                    let res = validate_p2pkh(prevTrnx, msgHash, transactionData, index);
                    if (res) { isVerify = true; continue; }
                    else isVerify = false; break;
                }
                if (prevTrnx.prevout.scriptpubkey_type === "p2sh") {
                    let res = validate_p2sh(prevTrnx, msgHash, transactionData, index);
                    if (res) { isVerify = true; continue; }
                    else isVerify = false; break;
                }
                if (prevTrnx.prevout.scriptpubkey_type === "v0_p2wpkh") {
                    let res = validate_p2wpkh(prevTrnx, msgHash, transactionData, index);
                    if (res) { isVerify = true; continue; }
                    else isVerify = false; break;
                }
                if (prevTrnx.prevout.scriptpubkey_type === "v0_p2wsh") {
                    let res = validate_p2wsh(prevTrnx, msgHash, transactionData, index);
                    if (res) { isVerify = true; continue; }
                    else isVerify = false; break;
                }
                if (prevTrnx.prevout.scriptpubkey_type === "v1_p2tr") {
                    isVerify = true;
                    continue;
                }
            }
            if (isVerify) {
                const txid = Buffer.from(sha256(Buffer.from(sha256(Buffer.from(msgHash.slice(0, -8), 'hex')), 'hex')), 'hex').reverse().toString('hex');
                transactions.push(txid) //push the txid 
                amt += input_value - output_value;
            }
        }
    });
    const transactionIDs = [...transactions.map(tx => tx)];
    /* const out = transactions.map(tx => `"${tx}"`).join(',\n');
    const outputString = `[${out}]`;
    fs.writeFileSync('invalid.txt', outputString); */
    merkleRoot = generateMerkleRoot(transactionIDs)
    /* console.log(merkleRoot) */
    const blockHeader = mineBlock(merkleRoot);

    const coinbaseTransaction = coinBaseTransaction(amt, merkleRoot); // Constructing coinbase transaction

    const output = `${blockHeader}\n${coinbaseTransaction}\n${transactionIDs.join('\n')}`;
    fs.writeFileSync('output.txt', output);
}

main()