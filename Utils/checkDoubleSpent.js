let utxoSet = {};

export function addToUTXOSet(txid, index) {
    if (utxoSet.hasOwnProperty(index)) {
        utxoSet[index].push(txid);
    } else {
        utxoSet[index] = [txid];
    }
}

export function isUnspent(txid, index) {
    if (utxoSet.hasOwnProperty(index)) {
        return utxoSet[index].includes(txid);
    }
    return false;
}

addToUTXOSet("tx1", 0);

console.log(isUnspent("tx1", 0)); 
