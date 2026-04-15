/**
 * ─────────────────────────────────────────────────────────────
 *  © 2026 MyCoin Project — PROPRIETARY AND CONFIDENTIAL
 *  All Rights Reserved. Unauthorized copying, modification,
 *  distribution, or use of this file is strictly prohibited.
 *  See LICENSE file in the project root for full details.
 * ─────────────────────────────────────────────────────────────
 */
'use strict';

const { Transaction, MIN_FEE } = require('../utxo/utxo');

const MAX_MEMPOOL_BYTES = parseInt(process.env.MEMPOOL_MAX_SIZE) || 50_000_000; // 50 MB
const MAX_MEMPOOL_TXS   = parseInt(process.env.MEMPOOL_MAX_TXS)  || 10_000;
const TX_EXPIRY_MS      = parseInt(process.env.TX_EXPIRY)        || 72 * 3_600_000; // 72 h
const MAX_ANCESTORS     = 25;

class Mempool {
    constructor() {
        this.txs       = new Map();     // txid → entry
        this.byFeeRate = [];            // entries sorted by fee rate (high → low)
        this.spentOuts = new Set();     // "txid:vout" keys spent by mempool txs
        this.totalSize = 0;
        this.seenTxids = new Set();     // replay protection cache

        // Evict expired transactions every 10 minutes
        setInterval(() => this._evictExpired(), 600_000);
    }

    // ── Add transaction to mempool ────────────────────────────
    add(tx, utxoSet) {
        if (this.txs.has(tx.id))
            return { ok: false, error: 'Transaction already in mempool' };
        if (this.seenTxids.has(tx.id))
            return { ok: false, error: 'Replay attack: transaction ID already seen' };

        // Validate against UTXO set
        const txObj = tx instanceof Transaction ? tx : Object.assign(new Transaction({}), tx);
        const { valid, errors } = txObj.validate(utxoSet, 0, {});
        if (!valid) return { ok: false, error: errors.join('; ') };

        // Check for conflicts with other mempool transactions
        for (const inp of tx.inputs || []) {
            const key = `${inp.txid}:${inp.vout}`;
            if (this.spentOuts.has(key))
                return { ok: false, error: `Conflict: ${key} is already spent in mempool` };
        }

        // Enforce capacity limits
        const txSize = txObj.size ? txObj.size() : JSON.stringify(tx).length;
        if (this.totalSize + txSize > MAX_MEMPOOL_BYTES) {
            this._evictLowFee(txSize);
            if (this.totalSize + txSize > MAX_MEMPOOL_BYTES)
                return { ok: false, error: 'Mempool is full (size limit)' };
        }
        if (this.txs.size >= MAX_MEMPOOL_TXS)
            return { ok: false, error: `Mempool is full (${MAX_MEMPOOL_TXS} tx limit)` };

        // Record the entry
        const entry = {
            tx,
            size:    txSize,
            fee:     BigInt(tx.fee || 0),
            feeRate: txSize > 0 ? Number(BigInt(tx.fee || 0)) / txSize : 0,
            addedAt: Date.now(),
        };

        this.txs.set(tx.id, entry);
        this.seenTxids.add(tx.id);
        this.totalSize += txSize;

        for (const inp of tx.inputs || [])
            this.spentOuts.add(`${inp.txid}:${inp.vout}`);

        this._insertSorted(entry);
        return { ok: true, txid: tx.id };
    }

    // ── Remove a transaction (e.g. after confirmation) ────────
    remove(txid) {
        const entry = this.txs.get(txid);
        if (!entry) return false;
        this.txs.delete(txid);
        this.totalSize -= entry.size;
        for (const inp of entry.tx.inputs || [])
            this.spentOuts.delete(`${inp.txid}:${inp.vout}`);
        this.byFeeRate = this.byFeeRate.filter(e => e.tx.id !== txid);
        return true;
    }

    // ── Remove confirmed transactions from mempool ────────────
    removeConfirmed(confirmedTxs) {
        for (const tx of confirmedTxs)
            this.remove(tx.id || tx);
    }

    // ── Get top N transactions by fee rate ────────────────────
    getTopN(n = 500) {
        return this.byFeeRate.slice(0, n).map(e => e.tx);
    }

    // ── Fetch a single transaction ────────────────────────────
    get(txid) {
        const entry = this.txs.get(txid);
        return entry ? entry.tx : null;
    }

    size()       { return this.txs.size; }
    byteSize()   { return this.totalSize; }

    totalFees() {
        let total = 0n;
        for (const entry of this.txs.values()) total += entry.fee;
        return total;
    }

    // ── Internal helpers ──────────────────────────────────────
    _insertSorted(entry) {
        // Binary insert to maintain fee-rate order (desc)
        let lo = 0, hi = this.byFeeRate.length;
        while (lo < hi) {
            const mid = (lo + hi) >> 1;
            if (this.byFeeRate[mid].feeRate > entry.feeRate) lo = mid + 1;
            else hi = mid;
        }
        this.byFeeRate.splice(lo, 0, entry);
    }

    _evictExpired() {
        const cutoff = Date.now() - TX_EXPIRY_MS;
        for (const [txid, entry] of this.txs) {
            if (entry.addedAt < cutoff) {
                this.remove(txid);
                console.log(`🗑️  Mempool: evicted expired tx ${txid.slice(0, 16)}`);
            }
        }
    }

    _evictLowFee(neededBytes) {
        // Remove lowest fee-rate txs until enough space is freed
        let freed = 0;
        for (let i = this.byFeeRate.length - 1; i >= 0 && freed < neededBytes; i--) {
            const entry = this.byFeeRate[i];
            freed += entry.size;
            this.remove(entry.tx.id);
            console.log(`🗑️  Mempool: evicted low-fee tx ${entry.tx.id.slice(0, 16)}`);
        }
    }

    // ── Statistics ────────────────────────────────────────────
    getStats() {
        return {
            count:     this.txs.size,
            bytes:     this.totalSize,
            totalFees: this.totalFees().toString(),
            minFeeRate: this.byFeeRate.length > 0
                ? this.byFeeRate[this.byFeeRate.length - 1].feeRate
                : 0,
            maxFeeRate: this.byFeeRate.length > 0
                ? this.byFeeRate[0].feeRate
                : 0,
        };
    }
}

module.exports = { Mempool };
