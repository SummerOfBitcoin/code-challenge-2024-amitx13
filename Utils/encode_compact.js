module.exports.encode_compact = (i) => {
    // Convert integer to a hex string with the correct prefix based on size
    let compactSize;
    if (i <= 252) {
        compactSize = Buffer.from(i.toString(16).padStart(2, "0"), "hex")
            .reverse()
            .toString("hex"); // Pack as 1-byte hex string
    } else if (i > 252 && i <= 65535) {
        compactSize =
            "fd" +
            Buffer.from(i.toString(16).padStart(4, "0"), "hex")
                .reverse()
                .toString("hex"); // Pack as 2-byte hex string with 'fd' prefix
    } else if (i > 65535 && i <= 4294967295) {
        compactSize =
            "fe" +
            Buffer.from(i.toString(16).padStart(8, "0"), "hex")
                .reverse()
                .toString("hex"); // Pack as 4-byte hex string with 'fe' prefix
    } else if (i > 4294967295 && i <= 18446744073709551615) {
        compactSize = "ff" + Buffer.from(i.toString(16).padStart(16, "0"), "hex")
            .reverse()
            .toString("hex"); // Pack as 8-byte hex string with 'ff' prefix
    }
    return compactSize;
}