/**
 * ─────────────────────────────────────────────────────────────
 *  © 2026 MyCoin Project — PROPRIETARY AND CONFIDENTIAL
 *  All Rights Reserved. Unauthorized copying, modification,
 *  distribution, or use of this file is strictly prohibited.
 *  See LICENSE file in the project root for full details.
 * ─────────────────────────────────────────────────────────────
 */
'use strict';

const crypto = require('crypto');
const { sha256d, merkleRoot, meetsTarget } = require('./crypto');
const { UTXOSet, Transaction, MAX_TX_SIZE } = require('../utxo/utxo');

// ── Chain constants ────────────────────────────────────────────
const GENESIS_HASH       = '0000000000000000000000000000000000000000000000000000000000000000';
const BLOCK_TIME_TARGET  = parseInt(process.env.BLOCK_TIME)       || 600_000;   // 10 min (ms)
const DIFFICULTY_WINDOW  = parseInt(process.env.DIFF_WINDOW)      || 2016;      // blocks
const MAX_BLOCK_SIZE     = parseInt(process.env.MAX_BLOCK_SIZE)   || 1_000_000; // 1 MB
const MAX_BLOCK_TXS      = parseInt(process.env.MAX_BLOCK_TXS)    || 3000;
const MIN_DIFFICULTY     = parseInt(process.env.MIN_DIFFICULTY)   || 1;
const MAX_DIFFICULTY     = 64;
const HALVING_INTERVAL   = parseInt(process.env.HALVING_INTERVAL) || 210_000;
const INITIAL_REWARD     = BigInt(process.env.INITIAL_REWARD      || '5000000000'); // 50 MYC
const CHAIN_ID           = parseInt(process.env.CHAIN_ID)         || 1;  // 1=mainnet 3=testnet

// ══════════════════════════════════════════════════════════════
//  BLOCK
// ══════════════════════════════════════════════════════════════
class Block {
    constructor({ height, timestamp, prevHash, merkleRoot: mr, difficulty, nonce,
                  transactions, hash, miner, chainId, version, bits, size }) {
        this.version      = version      || 1;
        this.height       = height       || 0;
        this.timestamp    = timestamp    || Date.now();
        this.prevHash     = prevHash     || GENESIS_HASH;
        this.merkleRoot   = mr           || '0'.repeat(64);
        this.difficulty   = difficulty   || MIN_DIFFICULTY;
        this.bits         = bits         || Block.diffToBits(difficulty || MIN_DIFFICULTY);
        this.nonce        = nonce        || 0;
        this.miner        = miner        || '';
        this.chainId      = chainId      || CHAIN_ID;
        this.transactions = transactions || [];
        this.hash         = hash         || this.computeHash();
        this.size         = size         || this._calcSize();
    }

    // Convert difficulty integer to compact bits field (Bitcoin-style)
    static diffToBits(difficulty) {
        const zeros = Math.min(difficulty, 56);
        return (0x1f000000 | (zeros << 16)).toString(16);
    }

    computeHash() {
        return sha256d(this._headerString());
    }

    _headerString() {
        return JSON.stringify({
            version:    this.version,
            height:     this.height,
            prevHash:   this.prevHash,
            merkleRoot: this.merkleRoot,
            timestamp:  this.timestamp,
            bits:       this.bits,
            nonce:      this.nonce,
            chainId:    this.chainId,
        });
    }

    _calcSize() {
        return JSON.stringify(this.transactions).length;
    }

    // ── Full block validation ──────────────────────────────────
    validate(prevBlock, utxoSet, blockHeight) {
        const errors = [];

        // Hash integrity check
        const computed = this.computeHash();
        if (computed !== this.hash)
            errors.push(`Invalid block hash: expected ${computed.slice(0, 8)}...`);

        // Proof of Work check
        if (!meetsTarget(this.hash, this.difficulty))
            errors.push(`PoW insufficient: hash ${this.hash.slice(0, 8)} with difficulty ${this.difficulty}`);

        // Previous hash link
        if (prevBlock && this.prevHash !== prevBlock.hash)
            errors.push(`Invalid prevHash: expected ${prevBlock.hash.slice(0, 8)}...`);

        // Height sequence
        if (prevBlock && this.height !== prevBlock.height + 1)
            errors.push(`Invalid height: expected ${prevBlock.height + 1}, got ${this.height}`);

        // Timestamp sanity (allow max 2h in the future)
        const now = Date.now();
        if (this.timestamp > now + 7_200_000)
            errors.push('Block timestamp too far in the future');
        if (prevBlock && this.timestamp < prevBlock.timestamp)
            errors.push('Block timestamp earlier than previous block');

        // Chain ID (replay protection)
        if (this.chainId !== CHAIN_ID)
            errors.push(`Wrong chainId: ${this.chainId} (expected ${CHAIN_ID})`);

        // Merkle root validation
        const txids      = this.transactions.map(tx => tx.id);
        const computedMR = merkleRoot(txids);
        if (computedMR !== this.merkleRoot)
            errors.push(`Invalid Merkle root: ${computedMR.slice(0, 8)} ≠ ${this.merkleRoot.slice(0, 8)}`);

        // Block size limits
        if (this.size > MAX_BLOCK_SIZE)
            errors.push(`Block too large: ${this.size} bytes > ${MAX_BLOCK_SIZE}`);
        if (this.transactions.length > MAX_BLOCK_TXS)
            errors.push(`Too many transactions: ${this.transactions.length} > ${MAX_BLOCK_TXS}`);

        // Coinbase requirement: exactly one, must be first
        const coinbases = this.transactions.filter(tx => tx.isCoinbase);
        if (coinbases.length !== 1)
            errors.push(`Expected exactly 1 coinbase transaction, got ${coinbases.length}`);
        if (this.transactions.length > 0 && !this.transactions[0].isCoinbase)
            errors.push('First transaction must be coinbase');

        // Coinbase reward check
        if (coinbases.length === 1) {
            const expectedReward = Block.getReward(blockHeight);
            const totalFees      = this.transactions
                .filter(tx => !tx.isCoinbase)
                .reduce((sum, tx) => sum + BigInt(tx.fee || 0), 0n);
            const coinbaseOut = coinbases[0].outputs
                .reduce((sum, o) => sum + BigInt(o.amount), 0n);
            if (coinbaseOut > expectedReward + totalFees)
                errors.push(`Coinbase reward too large: ${coinbaseOut} > ${expectedReward + totalFees}`);
        }

        // Validate all non-coinbase transactions
        const seenTxids  = new Set();
        const spentInBlock = new Set();

        for (const tx of this.transactions) {
            if (tx.isCoinbase) continue;

            if (seenTxids.has(tx.id)) {
                errors.push(`Duplicate transaction: ${tx.id.slice(0, 16)}`);
                continue;
            }
            seenTxids.add(tx.id);

            const txObj = Object.assign(new Transaction({}), tx);
            const { valid, errors: txErrors } = txObj.validate(utxoSet, blockHeight);
            if (!valid) errors.push(...txErrors.map(e => `TX ${tx.id.slice(0, 8)}: ${e}`));

            // Check for double-spend within the same block
            for (const inp of tx.inputs || []) {
                const key = `${inp.txid}:${inp.vout}`;
                if (spentInBlock.has(key))
                    errors.push(`Double-spend within block: ${key}`);
                spentInBlock.add(key);
            }
        }

        return { valid: errors.length === 0, errors };
    }

    // Calculate block subsidy at given height (with halving)
    static getReward(height) {
        const halvings = Math.floor(height / HALVING_INTERVAL);
        if (halvings >= 64) return 0n;
        return INITIAL_REWARD >> BigInt(halvings);
    }

    // Genesis block definition
    static genesis() {
        const genesisTx = new Transaction({
            id:         '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
            isCoinbase: true,
            inputs:     [{ txid: '0'.repeat(64), vout: 0xFFFFFFFF,
                           script: '4d79436f696e2047656e65736973', sequence: 0xFFFFFFFF }],
            outputs:    [{ address: 'genesis', amount: '5000000000' }],
            timestamp:  1,
        });

        return new Block({
            height:       0,
            version:      1,
            timestamp:    1,
            prevHash:     GENESIS_HASH,
            merkleRoot:   genesisTx.id,
            difficulty:   MIN_DIFFICULTY,
            bits:         Block.diffToBits(MIN_DIFFICULTY),
            nonce:        0,
            chainId:      CHAIN_ID,
            transactions: [genesisTx],
            hash:         '000' + '0'.repeat(61),
            miner:        'genesis',
        });
    }

    toJSON() {
        return {
            version:      this.version,
            height:       this.height,
            hash:         this.hash,
            prevHash:     this.prevHash,
            merkleRoot:   this.merkleRoot,
            timestamp:    this.timestamp,
            difficulty:   this.difficulty,
            bits:         this.bits,
            nonce:        this.nonce,
            miner:        this.miner,
            chainId:      this.chainId,
            size:         this.size,
            txCount:      this.transactions.length,
            transactions: this.transactions.map(tx =>
                typeof tx.toJSON === 'function' ? tx.toJSON() : tx
            ),
        };
    }
}

// ══════════════════════════════════════════════════════════════
//  BLOCKCHAIN
// ══════════════════════════════════════════════════════════════
class Blockchain {
    constructor() {
        const genesis     = Block.genesis();
        this.chain        = [genesis];
        this.utxoSet      = new UTXOSet();
        this.utxoSet.applyBlock(genesis, 0);
        this.bestHash     = genesis.hash;
        this.blockIndex   = new Map([[genesis.hash, genesis]]);
    }

    get height() { return this.chain.length - 1; }
    get tip()    { return this.chain[this.chain.length - 1]; }

    // ── Add a validated block to the chain ────────────────────
    addBlock(block) {
        const prevBlock = this.tip;
        const { valid, errors } = block.validate(prevBlock, this.utxoSet, this.chain.length);

        if (!valid) {
            console.error(`❌ Block rejected [${block.height}]:`, errors.join('; '));
            return { ok: false, error: errors.join('; ') };
        }

        this.chain.push(block);
        this.blockIndex.set(block.hash, block);
        this.utxoSet.applyBlock(block, block.height);
        this.bestHash = block.hash;

        console.log(`✅ Block [${block.height}] accepted | hash=${block.hash.slice(0, 16)} | txs=${block.transactions.length} | diff=${block.difficulty}`);
        return { ok: true, block };
    }

    // ── Chain Reorganization ──────────────────────────────────
    replaceChain(newChain) {
        if (newChain.length <= this.chain.length)
            return { replaced: false, reason: 'New chain is not longer than current chain' };

        const { valid, errors } = this.validateChain(newChain);
        if (!valid) return { replaced: false, reason: errors.join('; ') };

        const forkHeight = this._findForkHeight(newChain);
        console.warn(`⚠️  Chain reorg: fork at height ${forkHeight}, new length ${newChain.length}`);

        // Undo blocks back to fork point
        for (let i = this.chain.length - 1; i > forkHeight; i--)
            this.utxoSet.undoBlock(this.chain[i]);

        // Apply new blocks from fork point
        this.chain = newChain.slice(0, forkHeight + 1);
        for (let i = forkHeight + 1; i < newChain.length; i++) {
            this.utxoSet.applyBlock(newChain[i], i);
            this.chain.push(newChain[i]);
            this.blockIndex.set(newChain[i].hash, newChain[i]);
        }

        this.bestHash = this.tip.hash;
        return { replaced: true, forkHeight };
    }

    _findForkHeight(newChain) {
        for (let i = Math.min(this.chain.length, newChain.length) - 1; i >= 0; i--)
            if (this.chain[i]?.hash === newChain[i]?.hash) return i;
        return 0;
    }

    // ── Full chain validation ──────────────────────────────────
    validateChain(chain = this.chain) {
        const errors   = [];
        const tempUTXO = new UTXOSet();
        tempUTXO.applyBlock(chain[0], 0);

        for (let i = 1; i < chain.length; i++) {
            const { valid, errors: blkErrors } = chain[i].validate(chain[i - 1], tempUTXO, i);
            if (!valid) {
                errors.push(`Block ${i} invalid: ` + blkErrors.join('; '));
                break;
            }
            tempUTXO.applyBlock(chain[i], i);
        }

        return {
            valid:         errors.length === 0,
            errors,
            blocksChecked: errors.length === 0 ? chain.length : chain.length - 1,
        };
    }

    // ── Difficulty Adjustment (Bitcoin-style) ─────────────────
    getNextDifficulty() {
        const height = this.chain.length - 1;
        if (height < DIFFICULTY_WINDOW || height % DIFFICULTY_WINDOW !== 0)
            return this.tip.difficulty;

        const windowStart = this.chain[height - DIFFICULTY_WINDOW + 1];
        const windowEnd   = this.tip;
        const actualTime  = windowEnd.timestamp - windowStart.timestamp;
        const targetTime  = BLOCK_TIME_TARGET * DIFFICULTY_WINDOW;

        const cur = this.tip.difficulty;
        let   newDiff = Math.round(cur * targetTime / actualTime);

        // Cap adjustment at 4x in either direction
        newDiff = Math.max(Math.floor(cur / 4), Math.min(newDiff, cur * 4));
        newDiff = Math.max(MIN_DIFFICULTY, Math.min(MAX_DIFFICULTY, newDiff));

        console.log(`🔧 Difficulty: ${cur} → ${newDiff} (actual=${Math.round(actualTime / 1000)}s, target=${targetTime / 1000}s)`);
        return newDiff;
    }

    // ── Lookup helpers ────────────────────────────────────────
    getBlock(hash)         { return this.blockIndex.get(hash)    || null; }
    getBlockByHeight(h)    { return this.chain[h]                || null; }

    getTransaction(txid) {
        for (const block of [...this.chain].reverse()) {
            const tx = block.transactions.find(t => t.id === txid);
            if (tx) return { tx, block };
        }
        return null;
    }

    getBalance(address)  { return this.utxoSet.getBalance(address); }
    getUTXOs(address)    { return this.utxoSet.getUTXOs(address); }

    // ── Node statistics ───────────────────────────────────────
    getStats() {
        const tip = this.tip;
        const halvings = Math.floor(this.height / HALVING_INTERVAL);
        const currentReward = halvings >= 64 ? 0n : INITIAL_REWARD >> BigInt(halvings);
        return {
            height:        this.height,
            hash:          tip.hash,
            difficulty:    tip.difficulty,
            hashrate:      Math.pow(2, tip.difficulty),
            totalBlocks:   this.chain.length,
            utxoCount:     this.utxoSet.utxos.size,
            chainId:       CHAIN_ID,
            networkType:   CHAIN_ID === 1 ? 'mainnet' : 'testnet',
            miningReward:  currentReward.toString(),
            halvings,
            nextHalving:   (halvings + 1) * HALVING_INTERVAL,
        };
    }
}

// ── CPU Mining helper (testnet / development) ─────────────────
const { sha256d: _sha256d, meetsTarget: _meets, merkleRoot: _merkle } = require('./crypto');

Blockchain.prototype.mineBlock = function({ miner, transactions = [] }) {
    const prevBlock  = this.tip;
    const difficulty = this.getNextDifficulty();
    const height     = this.chain.length;

    const halvings = Math.floor(height / HALVING_INTERVAL);
    const reward   = halvings >= 64 ? 0n : INITIAL_REWARD >> BigInt(halvings);

    const coinbase = {
        id:         require('crypto').randomBytes(32).toString('hex'),
        isCoinbase: true,
        inputs:     [{ txid: '0'.repeat(64), vout: 0xFFFFFFFF, script: Buffer.from(`Height:${height}`).toString('hex'), sequence: 0xFFFFFFFF }],
        outputs:    [{ address: miner, amount: reward.toString() }],
        timestamp:  Date.now(),
    };

    const txList = [coinbase, ...transactions];
    const txids  = txList.map(t => t.id);
    const mr     = _merkle(txids);
    let nonce    = 0;
    const ts     = Date.now();

    while (nonce < 0x7FFFFFFF) {
        const candidate = new Block({
            height, timestamp: ts, prevHash: prevBlock.hash,
            merkleRoot: mr, difficulty, nonce, miner,
            transactions: txList, chainId: CHAIN_ID,
        });
        if (_meets(candidate.hash, difficulty)) {
            const result = this.addBlock(candidate);
            if (result.ok) return result;
            return { ok: false, error: result.error };
        }
        nonce++;
        if (nonce % 100_000 === 0) process.stdout.write('.');
    }
    return { ok: false, error: 'Nonce space exhausted' };
};

module.exports = {
    Blockchain, Block,
    GENESIS_HASH, BLOCK_TIME_TARGET, HALVING_INTERVAL, INITIAL_REWARD, CHAIN_ID,
};
