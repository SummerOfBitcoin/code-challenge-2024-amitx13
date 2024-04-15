module.exports.intToLittleEndianBytes = (n) => {
    const bytes = new Array(4).fill(0);
    for (let i = 0; i < 4; i++) {
        bytes[i] = (n >>> (i * 8)) & 0xFF;
    }
    return bytes;
}
