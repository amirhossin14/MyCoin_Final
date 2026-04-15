/**
 * ─────────────────────────────────────────────────────────────
 *  © 2026 MyCoin Project — PROPRIETARY AND CONFIDENTIAL
 *  All Rights Reserved. Unauthorized copying, modification,
 *  distribution, or use of this file is strictly prohibited.
 *  See LICENSE file in the project root for full details.
 * ─────────────────────────────────────────────────────────────
 */
'use strict';

const { sha256, sha256d, sign, verify, merkleRoot } = require('../blockchain/crypto');
const crypto = require('crypto');

// ── Constants ──────────────────────────────────────────────────
const SATOSHI          = 100_000_000n;  // 1 MYC = 10^8 satoshis
const MIN_FEE          = 1_000n;        // Minimum fee in satoshis
const DUST_THRESHOLD   = 546n;          // Minimum output value (no dust)
const MAX_TX_SIZE      = 100_000;       // Max transaction size in bytes
const TX_VERSION       = 1;
const COINBASE_MATURITY= 100;           // Blocks until coinbase is spendable
const FEE_PER_BYTE     = 10n;          // Satoshis per byte

// ══════════════════════════════════════════════════════════════
//  UTXO SET
// ══════════════════════════════════════════════════════════════
class UTXOSet {
    constructor() {
        this.utxos     = new Map();  // "txid:vout" → UTXO object
        this.byAddress = new Map();  // address → Set of UTXO keys
    }

    // ── Add a new UTXO ────────────────────────────────────────
    add(txid, vout, utxo) {
        const key = `${txid}:${vout}`;
        this.utxos.set(key, { ...utxo, txid, vout, key });
        if (!this.byAddress.has(utxo.address))
            this.byAddress.set(utxo.address, new Set());
        this.byAddress.get(utxo.address).add(key);
    }

    // ── Mark a UTXO as spent ──────────────────────────────────
    spend(txid, vout) {
        const key  = `${txid}:${vout}`;
        const utxo = this.utxos.get(key);
        if (!utxo) return false;
        this.utxos.delete(key);
        this.byAddress.get(utxo.address)?.delete(key);
        return true;
    }

    // ── Retrieve a UTXO by outpoint ───────────────────────────
    get(txid, vout) {
        return this.utxos.get(`${txid}:${vout}`) || null;
    }

    // ── Address balance (sum of all UTXOs) ────────────────────
    getBalance(address) {
        const keys = this.byAddress.get(address) || new Set();
        let total  = 0n;
        for (const key of keys) {
            const u = this.utxos.get(key);
            if (u) total += BigInt(u.amount);
        }
        return total;
    }

    // ── All UTXOs for an address (sorted largest first) ───────
    getUTXOs(address) {
        const keys   = this.byAddress.get(address) || new Set();
        const result = [];
        for (const key of keys) {
            const u = this.utxos.get(key);
            if (u) result.push(u);
        }
        return result.sort((a, b) => Number(BigInt(b.amount) - BigInt(a.amount)));
    }

    // ── Select coins to cover a target amount (greedy) ────────
    selectCoins(address, targetAmount) {
        const utxos    = this.getUTXOs(address);
        const selected = [];
        let   total    = 0n;
        const target   = BigInt(targetAmount);
        const baseFee  = this._estimateFee(1, 2);  // rough initial estimate

        for (const utxo of utxos) {
            if (total >= target + baseFee) break;
            selected.push(utxo);
            total += BigInt(utxo.amount);
        }

        if (total < target + MIN_FEE) return null;  // insufficient funds

        const fee    = this._estimateFee(selected.length, 2);
        const change = total - target - fee;

        if (total < target + fee) return null;

        return { selected, total, fee, change };
    }

    // Estimate fee based on transaction structure
    _estimateFee(inputCount, outputCount) {
        const estimatedBytes = inputCount * 148 + outputCount * 34 + 10;
        const fee = BigInt(estimatedBytes) * FEE_PER_BYTE;
        return fee < MIN_FEE ? MIN_FEE : fee;
    }

    // ── Apply all transactions in a block ─────────────────────
    applyBlock(block, blockHeight) {
        for (const tx of block.transactions)
            this.applyTx(tx, blockHeight);
    }

    applyTx(tx, blockHeight = 0) {
        // Spend inputs
        if (!tx.isCoinbase) {
            for (const inp of tx.inputs)
                this.spend(inp.txid, inp.vout);
        }
        // Create new outputs
        for (let i = 0; i < tx.outputs.length; i++) {
            const out = tx.outputs[i];
            this.add(tx.id, i, {
                address:      out.address,
                amount:       out.amount,
                blockHeight,
                isCoinbase:   tx.isCoinbase || false,
                matureHeight: tx.isCoinbase ? blockHeight + COINBASE_MATURITY : blockHeight,
            });
        }
    }

    // ── Undo a block (for chain reorg) ────────────────────────
    undoBlock(block) {
        for (const tx of [...block.transactions].reverse())
            this.undoTx(tx);
    }

    undoTx(tx) {
        // Remove new outputs
        for (let i = 0; i < tx.outputs.length; i++)
            this.spend(tx.id, i);
        // Restore spent inputs
        if (!tx.isCoinbase) {
            for (const inp of tx.inputs) {
                if (inp.prevOutput)
                    this.add(inp.txid, inp.vout, inp.prevOutput);
            }
        }
    }

    snapshot() {
        return {
            utxos:     Object.fromEntries(this.utxos),
            size:      this.utxos.size,
            addresses: this.byAddress.size,
        };
    }
}

// ══════════════════════════════════════════════════════════════
//  TRANSACTION
// ══════════════════════════════════════════════════════════════
class Transaction {
    constructor({ id, version, inputs, outputs, timestamp, isCoinbase, locktime, fee } = {}) {
        this.id         = id        || Transaction.computeId({ version, inputs, outputs, timestamp, locktime });
        this.version    = version   || TX_VERSION;
        this.inputs     = inputs    || [];
        this.outputs    = outputs   || [];
        this.timestamp  = timestamp || Date.now();
        this.isCoinbase = isCoinbase || false;
        this.locktime   = locktime  || 0;
        this.fee        = fee       || 0n;
    }

    static computeId(data) {
        return sha256d(JSON.stringify({
            version:   data.version,
            inputs:    (data.inputs || []).map(i => ({ txid: i.txid, vout: i.vout, sequence: i.sequence })),
            outputs:   data.outputs,
            timestamp: data.timestamp,
            locktime:  data.locktime,
        }));
    }

    // ── Create a coinbase transaction ─────────────────────────
    static createCoinbase({ blockHeight, minerAddress, reward, extraData = '' }) {
        const nonce   = crypto.randomBytes(8).toString('hex');
        const inputs  = [{
            txid:     '0'.repeat(64),
            vout:     0xFFFFFFFF,
            script:   Buffer.from(`${blockHeight}:${extraData}:${nonce}`).toString('hex'),
            sequence: 0xFFFFFFFF,
        }];
        const outputs = [{ address: minerAddress, amount: String(reward) }];
        const ts      = Date.now();
        return new Transaction({ version: TX_VERSION, inputs, outputs, timestamp: ts, isCoinbase: true, locktime: 0 });
    }

    // ── Create a signed regular transaction ───────────────────
    static create({ inputs, outputs, privateKey, timestamp }) {
        const ts     = timestamp || Date.now();
        const nonce  = crypto.randomBytes(4).toString('hex');
        const base   = { version: TX_VERSION, inputs, outputs, timestamp: ts, locktime: 0 };
        const txid   = Transaction.computeId(base);

        const signedInputs = inputs.map(inp => ({
            ...inp,
            nonce,
            signature: sign(privateKey,
                sha256(JSON.stringify({ txid, inp: inp.txid, vout: inp.vout, nonce }))),
        }));

        return new Transaction({ ...base, id: txid, inputs: signedInputs });
    }

    // ── Validate transaction ──────────────────────────────────
    validate(utxoSet, blockHeight = 0, options = {}) {
        const errors = [];

        if (this.isCoinbase) {
            if (this.inputs.length !== 1)  errors.push('Coinbase must have exactly 1 input');
            if (this.outputs.length === 0) errors.push('Coinbase must have at least 1 output');
            return { valid: errors.length === 0, errors };
        }

        // Timestamp checks
        const now        = Date.now();
        const MAX_FUTURE = 7_200_000;           // 2 hours
        const MAX_AGE    = 86_400_000 * 30;     // 30 days
        if (this.timestamp > now + MAX_FUTURE)  errors.push('Transaction timestamp too far in the future');
        if (this.timestamp < now - MAX_AGE)      errors.push('Transaction timestamp too old');

        if (!this.inputs?.length)  errors.push('Transaction has no inputs');
        if (!this.outputs?.length) errors.push('Transaction has no outputs');
        if (errors.length > 0) return { valid: false, errors };

        let inputTotal     = 0n;
        const seenOutpoints = new Set();

        for (const inp of this.inputs) {
            const key = `${inp.txid}:${inp.vout}`;
            if (seenOutpoints.has(key)) { errors.push(`Duplicate input: ${key}`); continue; }
            seenOutpoints.add(key);

            const utxo = utxoSet.get(inp.txid, inp.vout);
            if (!utxo) { errors.push(`UTXO not found: ${key}`); continue; }

            // Coinbase maturity check
            if (utxo.isCoinbase && blockHeight < utxo.matureHeight)
                errors.push(`Coinbase UTXO not yet mature: ${key} (need block ${utxo.matureHeight})`);

            // Signature verification (if pubkey is stored)
            if (utxo.pubkey || inp.pubkey) {
                const msgHash = sha256(JSON.stringify({ txid: this.id, inp: inp.txid, vout: inp.vout, nonce: inp.nonce }));
                if (!verify(utxo.pubkey || inp.pubkey, msgHash, inp.signature || ''))
                    errors.push(`Invalid signature for input: ${key}`);
            }

            inputTotal += BigInt(utxo.amount);
        }

        let outputTotal = 0n;
        for (const out of this.outputs) {
            const amount = BigInt(out.amount);
            if (amount < DUST_THRESHOLD) errors.push(`Output below dust threshold: ${amount} < ${DUST_THRESHOLD}`);
            if (!out.address)            errors.push('Output missing address');
            // Accept MYC-prefixed addresses (mainnet: MYC1, testnet: MYCt) or legacy format
            if (out.address && out.address !== 'genesis' &&
                !out.address.startsWith('*') &&
                !/^MYC[1t][A-Za-z0-9]{25,50}$/.test(out.address) &&
                !/^[A-Za-z0-9]{20,60}$/.test(out.address)) {
                errors.push('Invalid output address format: ' + out.address.slice(0, 16));
            }
            outputTotal += amount;
        }

        if (inputTotal < outputTotal)
            errors.push(`Input total (${inputTotal}) < output total (${outputTotal})`);

        // Compute fee
        const fee = inputTotal - outputTotal;
        this.fee  = fee;

        if (!options.skipFeeCheck && fee < MIN_FEE)
            errors.push(`Fee too low: ${fee} < ${MIN_FEE} (minimum)`);

        // Transaction size check
        if (this.size() > MAX_TX_SIZE)
            errors.push(`Transaction too large: ${this.size()} bytes`);

        return { valid: errors.length === 0, errors };
    }

    toJSON() {
        return {
            id:         this.id,
            version:    this.version,
            inputs:     this.inputs,
            outputs:    this.outputs,
            timestamp:  this.timestamp,
            isCoinbase: this.isCoinbase,
            locktime:   this.locktime,
            fee:        this.fee ? this.fee.toString() : '0',
        };
    }

    size() {
        return JSON.stringify(this.toJSON()).length;
    }
}

module.exports = { UTXOSet, Transaction, SATOSHI, MIN_FEE, DUST_THRESHOLD, MAX_TX_SIZE, COINBASE_MATURITY, FEE_PER_BYTE };
