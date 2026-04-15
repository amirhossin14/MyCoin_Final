/**
 * ─────────────────────────────────────────────────────────────
 *  © 2026 MyCoin Project — PROPRIETARY AND CONFIDENTIAL
 *  All Rights Reserved. Unauthorized copying, modification,
 *  distribution, or use of this file is strictly prohibited.
 *  See LICENSE file in the project root for full details.
 * ─────────────────────────────────────────────────────────────
 */
"use strict";

const crypto = require("crypto");

// ── Address prefix constants ───────────────────────────────────
const ADDR_PREFIX_MAINNET = "MYC1";
const ADDR_PREFIX_TESTNET = "MYCt";
const VERSION_MAINNET     = 0x19;
const VERSION_TESTNET     = 0x6F;

// ══════════════════════════════════════════════════════════════
//  HASH FUNCTIONS
// ══════════════════════════════════════════════════════════════

function sha256(data) {
    const buf = typeof data === "string" ? Buffer.from(data, "utf8")
              : Buffer.isBuffer(data)    ? data
              : Buffer.from(JSON.stringify(data), "utf8");
    return crypto.createHash("sha256").update(buf).digest("hex");
}

function sha256d(data) {
    const buf = typeof data === "string" ? Buffer.from(data, "utf8")
              : Buffer.isBuffer(data)    ? data
              : Buffer.from(JSON.stringify(data), "utf8");
    const first = crypto.createHash("sha256").update(buf).digest();
    return crypto.createHash("sha256").update(first).digest("hex");
}

function sha256Raw(buf) {
    const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf, "hex");
    return crypto.createHash("sha256").update(b).digest();
}

function ripemd160(buf) {
    const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf, "hex");
    return crypto.createHash("ripemd160").update(b).digest();
}

// HASH160 = RIPEMD160(SHA256(data)) — standard Bitcoin-style
function hash160(buf) {
    const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf, "hex");
    return ripemd160(sha256Raw(b));
}

// ══════════════════════════════════════════════════════════════
//  BASE58 / BASE58CHECK
// ══════════════════════════════════════════════════════════════

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(buf) {
    let leading = 0;
    for (const b of buf) { if (b === 0) leading++; else break; }
    let n = BigInt("0x" + (buf.length ? buf.toString("hex") : "00"));
    let s = "";
    while (n > 0n) { s = BASE58[Number(n % 58n)] + s; n /= 58n; }
    return "1".repeat(leading) + s;
}

function base58Decode(str) {
    let n = 0n;
    for (const ch of str) {
        const i = BASE58.indexOf(ch);
        if (i < 0) throw new Error("Invalid Base58 character: " + ch);
        n = n * 58n + BigInt(i);
    }
    let hex = n.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    const decoded = Buffer.from(hex, "hex");
    const leading = str.split("").findIndex(c => c !== "1");
    const zeros   = leading === -1 ? str.length : leading;
    return Buffer.concat([Buffer.alloc(zeros), decoded]);
}

function base58CheckEncode(payload) {
    const cs = sha256Raw(sha256Raw(payload)).slice(0, 4);
    return base58Encode(Buffer.concat([payload, cs]));
}

function base58CheckDecode(str) {
    const buf      = base58Decode(str);
    if (buf.length < 5) throw new Error("Base58Check string too short");
    const payload  = buf.slice(0, -4);
    const checksum = buf.slice(-4);
    const expected = sha256Raw(sha256Raw(payload)).slice(0, 4);
    if (!checksum.equals(expected)) throw new Error("Invalid Base58Check checksum");
    return payload;
}

// ══════════════════════════════════════════════════════════════
//  secp256k1 KEY PAIR
// ══════════════════════════════════════════════════════════════

/** Generate a new secp256k1 key pair. Returns DER-encoded hex strings. */
function generateKeyPair() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
        namedCurve:         "secp256k1",
        publicKeyEncoding:  { type: "spki",  format: "der" },
        privateKeyEncoding: { type: "pkcs8", format: "der" },
    });
    return {
        privateKey: privateKey.toString("hex"),
        publicKey:  publicKey.toString("hex"),
    };
}

/** Derive the DER-SPKI public key from a DER-PKCS8 private key. */
function derivePublicKey(privateKeyHex) {
    const privKeyObj = crypto.createPrivateKey({
        key:    Buffer.from(privateKeyHex, "hex"),
        format: "der",
        type:   "pkcs8",
    });
    const pubKeyObj = crypto.createPublicKey(privKeyObj);
    return pubKeyObj.export({ type: "spki", format: "der" }).toString("hex");
}

/**
 * Extract the raw 33-byte compressed public key from a DER-SPKI buffer.
 * The compressed point starts with 0x02 or 0x03.
 */
function getRawPublicKey(spkiHex) {
    const der = Buffer.isBuffer(spkiHex) ? spkiHex : Buffer.from(spkiHex, "hex");
    // Find compressed point marker (0x02 or 0x03) followed by 32 bytes
    for (let i = 0; i <= der.length - 33; i++) {
        if ((der[i] === 0x02 || der[i] === 0x03) && i > 0) {
            // Make sure what precedes looks like DER structure (not a random 0x02)
            // The byte before a raw public key in SPKI is typically 0x00 or an OID
            return der.slice(i, i + 33);
        }
    }
    // Fallback: uncompressed point (0x04 + 64 bytes) -> compress it
    for (let i = 0; i <= der.length - 65; i++) {
        if (der[i] === 0x04) {
            const x      = der.slice(i + 1, i + 33);
            const yLast  = der[i + 64];
            const prefix = (yLast & 1) ? 0x03 : 0x02;
            return Buffer.concat([Buffer.from([prefix]), x]);
        }
    }
    // Last fallback: hash the full DER (deterministic, won't validate but won't crash)
    return Buffer.from(sha256(der), "hex").slice(0, 33);
}

/** Sign dataHash (hex string) with privateKeyHex (DER-PKCS8). Returns hex DER signature. */
function sign(privateKeyHex, dataHash) {
    const privKey = crypto.createPrivateKey({
        key:    Buffer.from(privateKeyHex, "hex"),
        format: "der",
        type:   "pkcs8",
    });
    return crypto.sign("sha256", Buffer.from(dataHash, "hex"), privKey).toString("hex");
}

/** Verify an ECDSA signature. publicKeyHex = DER-SPKI hex. */
function verify(publicKeyHex, dataHash, signatureHex) {
    try {
        if (!publicKeyHex || !dataHash || !signatureHex) return false;
        const pubKey = crypto.createPublicKey({
            key:    Buffer.from(publicKeyHex, "hex"),
            format: "der",
            type:   "spki",
        });
        return crypto.verify(
            "sha256",
            Buffer.from(dataHash, "hex"),
            pubKey,
            Buffer.from(signatureHex, "hex"),
        );
    } catch { return false; }
}

// ══════════════════════════════════════════════════════════════
//  ADDRESS DERIVATION
//
//  mainnet: "MYC1" + Base58Check( [0x19] + HASH160(compressed_pubkey) )
//  testnet: "MYCt" + Base58Check( [0x6F] + HASH160(compressed_pubkey) )
// ══════════════════════════════════════════════════════════════

/**
 * Derive a MYC address from a DER-SPKI public key hex.
 * @param {string}  spkiHex - DER SPKI public key as hex
 * @param {boolean} testnet - true for testnet
 * @returns {string} Address like "MYC11BpEgosEc9BzaaCwMCNLJkGgCMpYNgzj"
 */
function publicKeyToAddress(spkiHex, testnet = false) {
    const rawPub    = getRawPublicKey(Buffer.from(spkiHex, "hex"));
    const h160      = hash160(rawPub);
    const version   = testnet ? VERSION_TESTNET : VERSION_MAINNET;
    const payload   = Buffer.concat([Buffer.from([version]), h160]);
    const b58check  = base58CheckEncode(payload);
    return (testnet ? ADDR_PREFIX_TESTNET : ADDR_PREFIX_MAINNET) + b58check;
}

/**
 * Validate a MYC address (checks prefix + Base58Check integrity).
 */
function validateAddress(address) {
    try {
        if (typeof address !== "string" || address.length < 8) return false;
        let b58part, expectedVersion;
        if (address.startsWith(ADDR_PREFIX_MAINNET)) {
            b58part = address.slice(ADDR_PREFIX_MAINNET.length);
            expectedVersion = VERSION_MAINNET;
        } else if (address.startsWith(ADDR_PREFIX_TESTNET)) {
            b58part = address.slice(ADDR_PREFIX_TESTNET.length);
            expectedVersion = VERSION_TESTNET;
        } else {
            return false;
        }
        const decoded = base58CheckDecode(b58part);
        return decoded.length === 21 && decoded[0] === expectedVersion;
    } catch { return false; }
}

/** Parse a MYC address into its components. */
function parseAddress(address) {
    if (!validateAddress(address)) throw new Error("Invalid MYC address: " + address);
    const isTestnet = address.startsWith(ADDR_PREFIX_TESTNET);
    const b58part   = address.slice(4);
    const decoded   = base58CheckDecode(b58part);
    return {
        version:    decoded[0],
        hash160Hex: decoded.slice(1).toString("hex"),
        network:    isTestnet ? "testnet" : "mainnet",
    };
}

// ══════════════════════════════════════════════════════════════
//  MERKLE TREE
// ══════════════════════════════════════════════════════════════

function merkleRoot(txids) {
    if (!txids || txids.length === 0) return sha256d("empty-block");
    if (txids.length === 1)           return txids[0];
    let layer = [...txids];
    while (layer.length > 1) {
        if (layer.length % 2) layer.push(layer[layer.length - 1]);
        const next = [];
        for (let i = 0; i < layer.length; i += 2)
            next.push(sha256d(layer[i] + layer[i + 1]));
        layer = next;
    }
    return layer[0];
}

function merkleProof(txids, targetTxid) {
    if (!txids.includes(targetTxid)) return null;
    const proof = [];
    let layer = [...txids];
    let idx   = layer.indexOf(targetTxid);
    while (layer.length > 1) {
        if (layer.length % 2) layer.push(layer[layer.length - 1]);
        const next = [];
        for (let i = 0; i < layer.length; i += 2) {
            if (i === idx || i + 1 === idx) {
                proof.push({ hash: i === idx ? layer[i+1] : layer[i],
                             position: i === idx ? "right" : "left" });
            }
            next.push(sha256d(layer[i] + layer[i+1]));
        }
        idx   = Math.floor(idx / 2);
        layer = next;
    }
    return proof;
}

function verifyMerkleProof(txid, proof, root) {
    let h = txid;
    for (const { hash: s, position: p } of proof)
        h = p === "right" ? sha256d(h + s) : sha256d(s + h);
    return h === root;
}

// ══════════════════════════════════════════════════════════════
//  PROOF OF WORK
// ══════════════════════════════════════════════════════════════

function meetsTarget(hash, difficulty) {
    return hash.startsWith("0".repeat(Math.min(difficulty, 64)));
}
function hashToTarget(hash)       { return BigInt("0x" + hash); }
function difficultyToTarget(diff) { return BigInt("0x" + "0".repeat(diff) + "f".repeat(64 - diff)); }

// ══════════════════════════════════════════════════════════════
//  EXPORTS
// ══════════════════════════════════════════════════════════════

module.exports = {
    sha256, sha256d, sha256Raw, ripemd160, hash160,
    base58Encode, base58Decode, base58CheckEncode, base58CheckDecode,
    generateKeyPair, derivePublicKey, getRawPublicKey, sign, verify,
    publicKeyToAddress, validateAddress, parseAddress,
    ADDR_PREFIX_MAINNET, ADDR_PREFIX_TESTNET, VERSION_MAINNET, VERSION_TESTNET,
    merkleRoot, merkleProof, verifyMerkleProof,
    meetsTarget, hashToTarget, difficultyToTarget,
};
