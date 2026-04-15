/**
 * ─────────────────────────────────────────────────────────────
 *  © 2026 MyCoin Project — PROPRIETARY AND CONFIDENTIAL
 *  All Rights Reserved. Unauthorized copying, modification,
 *  distribution, or use of this file is strictly prohibited.
 *  See LICENSE file in the project root for full details.
 * ─────────────────────────────────────────────────────────────
 */
// ═══════════════════════════════════════════════════════════════
//  ⚙️  MyCoin Configuration — All settings in one place
// ═══════════════════════════════════════════════════════════════

const COIN = {
    NAME:           'MyCoin',
    SYMBOL:         'MYC',
    DECIMALS:       8,                 // 8 decimal places (like Bitcoin)
    ADDRESS_PREFIX: 'MYC',
    WEBSITE:        'https://mycoin.example.com',
    VERSION:        '4.0.0',
};

const BLOCKCHAIN = {
    INITIAL_DIFFICULTY: 3,
    BLOCK_TIME_TARGET:  600_000,       // 10 minutes in ms (like Bitcoin)
    DIFFICULTY_WINDOW:  2016,          // Retarget every 2016 blocks (like Bitcoin)
    MINING_REWARD:      50,            // Initial block reward in MYC
    HALVING_INTERVAL:   210_000,       // Halve reward every 210,000 blocks
    MAX_SUPPLY:         21_000_000,    // 21 million max supply
    MAX_BLOCK_SIZE:     1_000_000,     // 1MB
    MAX_BLOCK_TXS:      3_000,
    STARTING_BALANCE:   1_000,         // Initial wallet balance for testing
    COINBASE_MATURITY:  100,           // Blocks before coinbase can be spent
    MIN_DIFFICULTY:     1,
    MAX_DIFFICULTY:     64,
};

const NETWORK = {
    HTTP_PORT:     parseInt(process.env.PORT)           || 3000,
    STRATUM_PORT:  parseInt(process.env.STRATUM_PORT)   || 3333,
    P2P_PORT:      parseInt(process.env.P2P_PORT)       || 8333,
    MAX_PEERS:     parseInt(process.env.MAX_PEERS)      || 8,
    CHAIN_ID:      parseInt(process.env.CHAIN_ID)       || 1,   // 1=mainnet, 3=testnet
};

const MEMPOOL = {
    MAX_SIZE_BYTES: parseInt(process.env.MEMPOOL_MAX_SIZE) || 50_000_000,  // 50MB
    MAX_TXS:        parseInt(process.env.MEMPOOL_MAX_TXS)  || 10_000,
    TX_EXPIRY_MS:   parseInt(process.env.TX_EXPIRY)        || 72 * 3600_000, // 72 hours
    MIN_FEE_RATE:   10,  // satoshis per byte
};

const SECURITY = {
    JWT_SECRET:      process.env.JWT_SECRET     || require('crypto').randomBytes(32).toString('hex'),
    ACCESS_KEY:      process.env.ACCESS_KEY     || require('crypto').randomBytes(32).toString('hex'),
    TOKEN_TTL_MS:    8 * 60 * 60 * 1000,        // 8 hours
    REFRESH_TTL_DAYS:30,
    MAX_LOGIN_FAILS: 5,
    LOCKOUT_MS:      15 * 60 * 1000,            // 15 minutes
    BCRYPT_ROUNDS:   10,
};

// ── Internal constants ──────────────────────────────────────────
const INITIAL_REWARD   = BigInt(process.env.INITIAL_REWARD || '5000000000'); // 50 MYC in satoshi
const HALVING_INTERVAL = BLOCKCHAIN.HALVING_INTERVAL;
const CHAIN_ID         = NETWORK.CHAIN_ID;
const REWARD_INPUT     = { address: '*authorized-reward*' };
const SATOSHI          = 100_000_000n;

const GENESIS_DATA = {
    timestamp:  1,
    lastHash:   '------',
    hash:       'hash-one',
    difficulty: BLOCKCHAIN.INITIAL_DIFFICULTY,
    nonce:      0,
    data:       [],
};

module.exports = {
    COIN,
    BLOCKCHAIN,
    NETWORK,
    MEMPOOL,
    SECURITY,
    GENESIS_DATA,
    INITIAL_REWARD,
    HALVING_INTERVAL,
    CHAIN_ID,
    SATOSHI,
    REWARD_INPUT,
    // Legacy aliases
    MINE_RATE:        BLOCKCHAIN.BLOCK_TIME_TARGET,
    STARTING_BALANCE: BLOCKCHAIN.STARTING_BALANCE,
    MINING_REWARD:    BLOCKCHAIN.MINING_REWARD,
    INITIAL_DIFFICULTY: BLOCKCHAIN.INITIAL_DIFFICULTY,
};
