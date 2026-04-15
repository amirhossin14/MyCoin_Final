/**
 * ─────────────────────────────────────────────────────────────
 *  © 2026 MyCoin Project — PROPRIETARY AND CONFIDENTIAL
 *  All Rights Reserved. Unauthorized copying, modification,
 *  distribution, or use of this file is strictly prohibited.
 *  See LICENSE file in the project root for full details.
 * ─────────────────────────────────────────────────────────────
 */
'use strict';

const express = require('express');
const http    = require('http');
const path    = require('path');
const crypto  = require('crypto');

// ── Core modules ───────────────────────────────────────────────
const { Blockchain, CHAIN_ID, HALVING_INTERVAL, INITIAL_REWARD } = require('./blockchain/blockchain');
const { UTXOSet, Transaction, MIN_FEE, SATOSHI }                  = require('./utxo/utxo');
const { Mempool }                                                  = require('./mempool/mempool');
const { P2PServer }                                                = require('./p2p/p2p');
const { StratumServer }                                            = require('./mining-pool/stratum');
const { Wallet }                                                   = require('./wallet/wallet');

// ── Security ───────────────────────────────────────────────────
const { ac }                                         = require('./app/access-control');
const { jwtMiddleware, createTokens, verifyRefresh, revokeToken } = require('./middleware/jwt');
const { ddos, limiters, honeypot }                   = require('./middleware/ratelimit');
const {
    buildHoneypot, licenseHeaders, aiRateLimit,
    threatScorer, sessionBinder, anomalyDetect,
}                                                    = require('./middleware/security');

// ── Monitoring ─────────────────────────────────────────────────
const { metrics, httpMetricsMiddleware, metricsHandler, bindBlockchain } = require('./monitoring/metrics');

// ── Database ───────────────────────────────────────────────────
const { migrate, UserRepo, LogRepo, KYC, pool: dbPool } = require('./db/database');

// ── Config ─────────────────────────────────────────────────────
const { COIN, NETWORK } = require('./config');

// ══════════════════════════════════════════════════════════════
//  INPUT VALIDATION SCHEMA
// ══════════════════════════════════════════════════════════════
const V = {
    address:  a => typeof a === 'string' && (a.startsWith('MYC1') || a.startsWith('MYCt')) && /^MYC[1t][A-Za-z0-9]{25,50}$/.test(a),
    amount:   n => typeof n === 'number' && Number.isFinite(n) && n > 0 && n <= 21_000_000,
    txid:     s => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s),
    hash:     s => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s),
    username: s => typeof s === 'string' && /^[a-zA-Z0-9_]{3,32}$/.test(s),
    password: s => typeof s === 'string' && s.length >= 8 && s.length <= 128,
    ip:       s => typeof s === 'string' && /^(\d{1,3}\.){3}\d{1,3}$/.test(s),
};

function body(schema) {
    return (req, res, next) => {
        for (const [field, validate] of Object.entries(schema)) {
            if (req.body?.[field] === undefined)
                return res.status(400).json({ error: `Missing required field: ${field}` });
            if (!validate(req.body[field]))
                return res.status(400).json({ error: `Invalid value for field: ${field}` });
        }
        next();
    };
}

// ══════════════════════════════════════════════════════════════
//  CORE INITIALIZATION
// ══════════════════════════════════════════════════════════════
const blockchain = new Blockchain();
const mempool    = new Mempool();
const wallet     = new Wallet();
const p2p        = new P2PServer({ blockchain, mempool });
const stratum    = new StratumServer({ blockchain, mempool, wallet });

// Stratum → found block
stratum.on('block:found', ({ block, workerName }) => {
    const r = blockchain.addBlock(block);
    if (r.ok) {
        metrics.blockMined?.inc({ miner: workerName });
        p2p.broadcastBlock?.(block);
        stratum.broadcastNewJob(true);
    }
});

// P2P → received block from peer
p2p.on('block:received', ({ block }) => {
    const r = blockchain.addBlock(block);
    if (r.ok) stratum.broadcastNewJob(false);
});

// P2P → received transaction from peer
p2p.on('tx:received', ({ tx }) => mempool.add(tx, blockchain.utxoSet));

// ══════════════════════════════════════════════════════════════
//  EXPRESS APP
// ══════════════════════════════════════════════════════════════
const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by');

// ── Security headers ───────────────────────────────────────────
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options',  'nosniff');
    res.setHeader('X-Frame-Options',         'SAMEORIGIN');
    res.setHeader('X-XSS-Protection',        '1; mode=block');
    res.setHeader('Referrer-Policy',         'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy',      'geolocation=(), microphone=(), camera=()');
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data:; " +
        "connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com"
    );
    if (process.env.NODE_ENV === 'production')
        res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    next();
});

app.use(buildHoneypot(threatScorer));   // Extended honeypot (30+ bot traps)
app.use(ddos.middleware());
app.use(licenseHeaders());              // Inject copyright headers on all responses

// Anomaly detection — score suspicious IPs automatically
app.use((req, res, next) => {
    const ip = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    anomalyDetect.analyze(req);
    if (threatScorer.isDangerous(ip)) {
        console.warn(`🚨 [Security] Dangerous IP blocked: ${ip} (score ${threatScorer.get(ip)})`);
        return res.status(403).json({ error: 'Access denied', code: 'THREAT_DETECTED' });
    }
    next();
});

app.use(express.json({ limit: '100kb' }));

// ── Protect all server-side source files ──────────────────────
const BLOCKED_PATHS = /^\/(server|config|app_stratum|package|package-lock)(\.js|\.json)?$/i;
const BLOCKED_DIRS  = /^\/(app|blockchain|db|mempool|middleware|mining-pool|monitoring|p2p|utxo|wallet|cli|testnet|ha|docker|docs)(\/.*)?$/i;

app.use((req, res, next) => {
    const p = req.path.toLowerCase();
    if (BLOCKED_PATHS.test(p) || BLOCKED_DIRS.test(p))
        return res.status(403).json({ error: 'Access denied' });
    next();
});

// Admin & dashboard panels: no caching (always get fresh)
app.use(['/admin.html', '/dashboard.html'], (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    next();
});

app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

// Root → dashboard
app.get('/', (req, res) => res.redirect('/dashboard.html'));

// LICENSE — viewable by anyone (proof of ownership)
app.get('/LICENSE', (req, res) => {
    const fs   = require('fs');
    const path = require('path');
    const file = path.join(__dirname, 'LICENSE');
    if (!fs.existsSync(file)) return res.status(404).send('LICENSE file not found');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.send(fs.readFileSync(file, 'utf8'));
});
app.use(httpMetricsMiddleware);
app.use('/api/', limiters.global.middleware());

// ── Auth middleware factory ────────────────────────────────────
function auth(perm) {
    return [
        jwtMiddleware(false),
        (req, res, next) => {
            if (req.user) {
                if (perm && !ac.hasPerm(req.user, perm))
                    return res.status(403).json({ error: 'Permission denied', required: perm });
                return next();
            }
            return ac.middleware(perm)(req, res, next);
        },
    ];
}

// ── Audit log helper ───────────────────────────────────────────
async function log(req, action, details = {}) {
    await LogRepo.add({
        userId:    req.user?.id,
        username:  req.user?.username,
        role:      req.user?.role,
        action,
        ip:        req.ip,
        path:      req.path,
        userAgent: req.headers['user-agent'],
        details,
    }).catch(() => {});
}

// ══════════════════════════════════════════════════════════════
//  PUBLIC ENDPOINTS (no authentication required)
// ══════════════════════════════════════════════════════════════

app.get('/api/health', (req, res) => res.json({
    status:  'ok',
    version: '4.0.0',
    height:  blockchain.height,
    peers:   p2p.peerCount(),
    miners:  stratum.getStats().authorized,
    mempool: mempool.size(),
    chainId: CHAIN_ID,
    network: CHAIN_ID === 1 ? 'mainnet' : 'testnet',
    uptime:  Math.floor(process.uptime()),
}));

app.get('/api/coin-info', (req, res) => res.json({
    name:            COIN.NAME,
    symbol:          COIN.SYMBOL,
    decimals:        8,
    maxSupply:       '21000000',
    miningReward:    (Number(INITIAL_REWARD) / 1e8).toString(),
    halvingInterval: HALVING_INTERVAL,
    chainId:         CHAIN_ID,
    network:         CHAIN_ID === 1 ? 'mainnet' : 'testnet',
    version:         COIN.VERSION,
}));

// Prometheus metrics (internal network only in production)
app.get('/metrics', (req, res) => {
    const ip = req.ip || '';
    const allowed = ip.startsWith('172.') || ip.startsWith('10.') ||
                    ip === '127.0.0.1' || ip === '::1';
    if (!allowed && process.env.NODE_ENV === 'production')
        return res.status(403).end();
    metricsHandler(req, res);
});

// ── Public blockchain explorer endpoints ──────────────────────

app.get('/api/stats', (req, res) => {
    const s = blockchain.getStats();
    res.json({
        ...s,
        mempoolSize: mempool.size(),
        mempoolFees: mempool.totalFees ? mempool.totalFees().toString() : '0',
        peers:       p2p.peerCount(),
        nodeAddress: wallet.address || wallet.publicKey,
        coin:        { name: COIN.NAME, symbol: COIN.SYMBOL },
    });
});

app.get('/api/blocks', (req, res) => {
    const page  = Math.max(1, parseInt(req.query.page)  || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 10);
    const all   = [...blockchain.chain].reverse();
    res.json({
        blocks: all.slice((page - 1) * limit, page * limit),
        total:  blockchain.chain.length,
        page,
        pages:  Math.ceil(blockchain.chain.length / limit),
    });
});

app.get('/api/block/:ref', (req, res) => {
    const ref = req.params.ref;
    const block = /^\d+$/.test(ref)
        ? blockchain.getBlockByHeight(+ref)
        : blockchain.getBlock(ref);
    if (!block) return res.status(404).json({ error: 'Block not found' });
    res.json(block);
});

app.get('/api/tx/:txid', (req, res) => {
    if (!V.txid(req.params.txid))
        return res.status(400).json({ error: 'Invalid transaction ID format' });
    const r = blockchain.getTransaction(req.params.txid);
    if (!r) {
        const pending = mempool.get?.(req.params.txid);
        if (pending) return res.json({ ...pending, status: 'pending', confirmations: 0 });
        return res.status(404).json({ error: 'Transaction not found' });
    }
    res.json({
        ...r.tx,
        blockHash:     r.block.hash,
        blockHeight:   r.block.height,
        confirmations: blockchain.height - r.block.height + 1,
        status:        'confirmed',
    });
});

app.get('/api/address/:addr', (req, res) => {
    if (!V.address(req.params.addr) && !/^MYC[1t][A-Za-z0-9]{25,50}$/.test(req.params.addr))
        return res.status(400).json({ error: 'Invalid MYC address format (expected MYC1... or MYCt...)' });
    const addr    = req.params.addr;
    const balance = blockchain.utxoSet.getBalance(addr);
    const utxos   = blockchain.utxoSet.getUTXOs(addr);
    res.json({
        address:    addr,
        balance:    balance.toString(),
        balanceMYC: (Number(balance) / 1e8).toFixed(8),
        utxoCount:  utxos.length,
        utxos,
    });
});

// Compatibility: legacy wallet lookup (used by dashboard)
app.get('/api/wallet/:addr', (req, res) => {
    const addr    = req.params.addr;
    const balance = blockchain.utxoSet.getBalance(addr);
    const utxos   = blockchain.utxoSet.getUTXOs(addr);
    const txList  = [];
    for (const block of blockchain.chain) {
        for (const tx of block.transactions || []) {
            const involves = (tx.outputs||[]).some(o=>o.address===addr)
                          || (tx.inputs ||[]).some(i=>i.address===addr);
            if (involves) txList.push({ ...tx, blockHash: block.hash, blockTime: block.timestamp });
        }
    }
    res.json({
        address: addr,
        balance: balance.toString(),
        balanceMYC: (Number(balance)/1e8).toFixed(8),
        symbol: COIN.SYMBOL,
        utxoCount: utxos.length,
        utxos,
        transactions: txList.slice(-50),
    });
});

app.get('/api/search/:q', (req, res) => {
    const q = req.params.q.trim();
    if (V.hash(q)) {
        const block = blockchain.getBlock(q);
        if (block) return res.json({ type: 'block', data: block });
        const tx = blockchain.getTransaction(q);
        if (tx) return res.json({ type: 'transaction', data: { ...tx.tx, blockHash: tx.block.hash } });
    }
    if (/^\d+$/.test(q)) {
        const block = blockchain.getBlockByHeight(+q);
        if (block) return res.json({ type: 'block', data: block });
    }
    if (V.address(q)) {
        const balance = blockchain.utxoSet.getBalance(q);
        return res.json({ type: 'address', data: { address: q, balance: balance.toString() } });
    }
    res.status(404).json({ error: 'Not found' });
});

// ══════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════════
const authRouter = express.Router();
authRouter.use(limiters.auth.middleware());

authRouter.post('/login', body({ username: V.username, password: V.password }), async (req, res) => {
    const { username, password, totp } = req.body;
    const result = ac.login({ username, password, totp: totp || null, ip: req.ip });
    if (!result.ok) {
        metrics.loginTotal?.inc({ result: 'failed' });
        await log(req, 'login:failed', { reason: result.error });
        const status = result.require2fa ? 200 : 401;
        return res.status(status).json({ error: result.error, require2fa: result.require2fa || false });
    }
    const tokens = createTokens(result.user);
    metrics.loginTotal?.inc({ result: 'success' });
    await log({ ...req, user: result.user }, 'login');
    res.json({ ...tokens, user: { username: result.user.username, role: result.user.role } });
});

authRouter.post('/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token not provided' });
    try {
        const payload = verifyRefresh(refreshToken);
        const user    = ac.getUserById(payload.sub);
        if (!user) return res.status(401).json({ error: 'User not found' });
        revokeToken(refreshToken);
        res.json(createTokens(user));
    } catch {
        res.status(401).json({ error: 'Invalid or expired refresh token' });
    }
});

authRouter.post('/logout', jwtMiddleware(false), async (req, res) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (token) { revokeToken(token); ac.logout(token, req.ip); }
    if (req.user) await log(req, 'logout');
    res.json({ ok: true });
});

authRouter.get('/me', jwtMiddleware(), (req, res) => {
    const u = ac.getUserById(req.user.id);
    if (!u) return res.status(401).json({ error: 'User not found' });
    const totp = ac.getTotpStatus(req.user.id);
    res.json({ id: u.id, username: u.username, role: u.role, permissions: u.permissions, totpEnabled: totp.enabled });
});

// ── TOTP / 2FA routes ──────────────────────────────────────────

authRouter.post('/2fa/setup', jwtMiddleware(), (req, res) => {
    const result = ac.setupTotp(req.user.id);
    if (!result.ok) return res.status(400).json(result);
    res.json(result);
});

authRouter.post('/2fa/confirm', jwtMiddleware(), (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'TOTP code is required' });
    const result = ac.confirmTotp(req.user.id, token.toString());
    if (!result.ok) return res.status(400).json(result);
    res.json(result);
});

authRouter.post('/2fa/disable', jwtMiddleware(), (req, res) => {
    const { token } = req.body;
    const result = ac.disableTotp(req.user.id, (token || '').toString());
    if (!result.ok) return res.status(400).json(result);
    res.json(result);
});

authRouter.get('/2fa/status', jwtMiddleware(), (req, res) => {
    res.json(ac.getTotpStatus(req.user.id));
});

// ── Change password ────────────────────────────────────────────
authRouter.post('/change-password', jwtMiddleware(), async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword)
        return res.status(400).json({ error: 'Both oldPassword and newPassword are required' });
    if (newPassword.length < 8)
        return res.status(400).json({ error: 'New password must be at least 8 characters' });
    const u = ac.getUserById(req.user.id);
    if (!u) return res.status(404).json({ error: 'User not found' });
    const test = ac.login({ username: u.username, password: oldPassword, ip: req.ip });
    if (!test.ok) return res.status(400).json({ error: 'Current password is incorrect' });
    const r = ac.updateUser(req.user.id, { password: newPassword });
    if (!r.ok) return res.status(400).json(r);
    await log(req, 'password:changed');
    res.json({ ok: true });
});

app.use('/api/auth', authRouter);

// ══════════════════════════════════════════════════════════════
//  MEMPOOL
// ══════════════════════════════════════════════════════════════
app.get('/api/mempool', auth('view:transactions'), (req, res) => {
    const limit = Math.min(100, parseInt(req.query.limit) || 50);
    res.json({
        count: mempool.size(),
        bytes: mempool.byteSize?.() || 0,
        txs:   mempool.getTopN(limit),
        stats: mempool.getStats?.(),
    });
});

// ══════════════════════════════════════════════════════════════
//  WALLET & TRANSACTIONS
// ══════════════════════════════════════════════════════════════
app.get('/api/wallet-info', auth('view:wallet'), (req, res) => {
    const addr = wallet.address || wallet.publicKey;
    const bal  = blockchain.utxoSet.getBalance(addr);
    res.json({
        address:    addr,
        publicKey:  wallet.publicKey,
        balance:    bal.toString(),
        balanceMYC: (Number(bal) / 1e8).toFixed(8),
        symbol:     COIN.SYMBOL,
    });
});

app.post('/api/transact',
    auth('transact:send'),
    limiters.api.middleware(),
    body({ recipient: V.address, amount: V.amount }),
    async (req, res) => {
        const { recipient, amount } = req.body;
        try {
            const satoshis = BigInt(Math.round(amount * 1e8));
            const tx = wallet.buildTransaction
                ? wallet.buildTransaction({ to: recipient, amount: satoshis, utxoSet: blockchain.utxoSet, feeRate: 10 })
                : wallet.createTransaction({ recipient, amount, chain: blockchain.chain });
            const r = mempool.add(tx, blockchain.utxoSet);
            if (!r.ok) return res.status(400).json({ error: r.error });
            p2p.broadcastTx?.(tx);
            await log(req, 'transaction:sent', { recipient: recipient.slice(0, 20), amount, txid: tx.id });
            res.json({ ok: true, txid: tx.id, transaction: tx });
        } catch (e) {
            res.status(400).json({ error: e.message });
        }
    }
);

app.post('/api/broadcast', auth('transact:send'), async (req, res) => {
    const { tx } = req.body;
    if (!tx || typeof tx !== 'object')
        return res.status(400).json({ error: 'Invalid transaction object' });
    const txObj = Object.assign(new Transaction({}), tx);
    const { valid, errors } = txObj.validate
        ? txObj.validate(blockchain.utxoSet, blockchain.height, {})
        : { valid: true, errors: [] };
    if (!valid) return res.status(400).json({ error: errors.join('; ') });
    const r = mempool.add(txObj, blockchain.utxoSet);
    if (!r.ok) return res.status(400).json({ error: r.error });
    p2p.broadcastTx?.(txObj);
    res.json({ ok: true, txid: txObj.id });
});

// ══════════════════════════════════════════════════════════════
//  MINING
// ══════════════════════════════════════════════════════════════
app.post('/api/mine',
    auth('mine:blocks'),
    limiters.mining.middleware(),
    async (req, res) => {
        // CPU mining only allowed on testnet
        if (CHAIN_ID === 1 && process.env.NODE_ENV === 'production')
            return res.status(403).json({ error: 'Use Stratum protocol for mainnet mining' });
        try {
            const txs = mempool.getTopN(500);
            const r   = blockchain.mineBlock
                ? blockchain.mineBlock({ miner: wallet.address || wallet.publicKey, transactions: txs })
                : { ok: false, error: 'mineBlock not available' };
            if (!r.ok) return res.status(400).json({ error: r.error });
            mempool.removeConfirmed?.(r.block.transactions);
            p2p.broadcastBlock?.(r.block);
            stratum.broadcastNewJob(true);
            await log(req, 'block:mined', { height: r.block.height, txCount: r.block.transactions.length });
            res.json({ ok: true, block: r.block });
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    }
);

// ══════════════════════════════════════════════════════════════
//  STRATUM & P2P
// ══════════════════════════════════════════════════════════════
app.get('/api/stratum/stats',     auth('view:miners'), (req, res) => res.json(stratum.getStats()));
app.get('/api/stratum/banlist',   auth('mine:blocks'), (req, res) => res.json(stratum.getBanList()));
app.delete('/api/stratum/ban/:ip', auth('admin:users'), (req, res) => {
    stratum.unban(req.params.ip); res.json({ ok: true });
});
app.post('/api/stratum/new-job',  auth('mine:blocks'), (req, res) => {
    stratum.broadcastNewJob(true); res.json({ ok: true });
});

app.get('/api/peers', auth('view:dashboard'), (req, res) =>
    res.json({ count: p2p.peerCount(), peers: p2p.getPeers?.() || [] })
);
app.post('/api/peers/connect', auth('admin:users'), (req, res) => {
    const { host, port } = req.body;
    if (!host || !port) return res.status(400).json({ error: 'host and port are required' });
    p2p.connectToPeer?.(`ws://${host}:${port}`);
    res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  KYC
// ══════════════════════════════════════════════════════════════
app.get('/api/kyc/status', auth('view:wallet'), async (req, res) => {
    try {
        res.json({ status: await KYC.getStatus(req.user.id), limits: await KYC.getLimits(req.user.id) });
    } catch { res.json({ status: null, limits: null }); }
});
app.post('/api/kyc/submit', auth('view:wallet'), async (req, res) => {
    try {
        const r = await KYC.submit(req.user.id, req.body);
        res.json({ ok: true, id: r.id });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
//  ADMIN
// ══════════════════════════════════════════════════════════════
app.get('/api/admin/users',        auth('admin:users'), (req, res) => res.json(ac.getUsers()));

app.post('/api/admin/users',       auth('admin:users'),
    body({ username: V.username, password: V.password }),
    async (req, res) => {
        const r = ac.createUser(req.body, req.user.username);
        if (!r.ok) return res.status(400).json({ error: r.error });
        await log(req, 'user:created', { target: req.body.username });
        res.json(r);
    }
);

app.put('/api/admin/users/:id',    auth('admin:users'), (req, res) =>
    res.json(ac.updateUser(req.params.id, req.body, req.user.username))
);

app.delete('/api/admin/users/:id', auth('admin:users'), async (req, res) => {
    const r = ac.deleteUser(req.params.id, req.user.username);
    if (r.ok) await log(req, 'user:deleted', { targetId: req.params.id });
    res.json(r);
});

app.get('/api/admin/apikeys',          auth('admin:apikeys'), (req, res) => res.json(ac.getApiKeys()));
app.post('/api/admin/apikeys',         auth('admin:apikeys'), (req, res) =>
    res.json(ac.createApiKey({ name: req.body.name, role: req.body.role }, req.user.username))
);
app.delete('/api/admin/apikeys/:id',   auth('admin:apikeys'), (req, res) =>
    res.json(ac.revokeApiKey(req.params.id, req.user.username))
);

app.get('/api/admin/logs', auth('admin:logs'), async (req, res) => {
    try {
        const { limit = 200, username, action, role } = req.query;
        const logs = await LogRepo.list({
            username, action, role, limit: Math.min(+limit, 1000),
        }).catch(() => ac.getLogs(+limit, { username, action, role }));
        res.json(logs);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/kyc/pending',       auth('admin:users'), async (req, res) => {
    try { res.json(await KYC.getPending()); } catch { res.json([]); }
});
app.put('/api/admin/kyc/:id/review',    auth('admin:users'), async (req, res) => {
    try {
        const r = await KYC.review(req.params.id, req.user.id, req.body.approved, req.body.reason);
        res.json({ ok: true, result: r });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/admin/ddos/stats',        auth('admin:users'), (req, res) => res.json(ddos.getStats()));
app.post('/api/admin/ddos/block',       auth('admin:users'), (req, res) => {
    if (!V.ip(req.body.ip)) return res.status(400).json({ error: 'Invalid IP address' });
    ddos.blockIP(req.body.ip, req.body.duration);
    res.json({ ok: true });
});
app.delete('/api/admin/ddos/block/:ip', auth('admin:users'), (req, res) => {
    ddos.unblockIP(req.params.ip); res.json({ ok: true });
});

app.get('/api/admin/chain/validate',    auth('admin:users'), (req, res) => {
    const result = blockchain.validateChain();
    res.json({ ...result, checkedAt: new Date().toISOString() });
});

app.get('/api/admin/mempool/stats',     auth('admin:users'), (req, res) =>
    res.json(mempool.getStats?.() || { count: mempool.size() })
);

// ══════════════════════════════════════════════════════════════
//  🤖 AI ASSISTANT — Claude (Anthropic Free Tier)
//  Provides blockchain intelligence: tx analysis, mining help,
//  address lookup explanations, and general MyCoin Q&A.
// ══════════════════════════════════════════════════════════════

// Inline context builder — injects live blockchain data into AI prompt
function buildBlockchainContext() {
    const stats = blockchain.getStats();
    const tip   = blockchain.tip;
    return `You are MyCoin AI — an expert assistant for the MyCoin blockchain.
Current network status:
- Chain height: ${stats.height} blocks
- Network: ${stats.networkType}
- Current difficulty: ${stats.difficulty}
- UTXO set size: ${stats.utxoCount} outputs
- Latest block hash: ${tip.hash.slice(0, 16)}...
- Mining reward: ${Number(stats.miningReward || 0) / 1e8} MYC per block
- Halvings so far: ${stats.halvings || 0}
- Mempool: ${mempool.size()} pending transactions
- Connected peers: ${p2p.peerCount()}

You help users with: transaction questions, wallet addresses (MYC1.../MYCt...), 
mining, block explorer queries, security, and general blockchain concepts.
Keep answers concise and technical. Do NOT provide financial advice.
Always answer in the same language the user writes in.`;
}

app.post('/api/ai/chat',
    auth('view:dashboard'),
    aiRateLimit,
    async (req, res) => {
        const { message, history = [] } = req.body;
        if (!message || typeof message !== 'string' || message.length > 2000) {
            return res.status(400).json({ error: 'Invalid message (max 2000 chars)' });
        }

        try {
            const systemPrompt = buildBlockchainContext();

            // Build message history (max last 10 turns)
            const messages = [
                ...history.slice(-10).map(m => ({
                    role:    m.role === 'user' ? 'user' : 'assistant',
                    content: String(m.content).slice(0, 1000)
                })),
                { role: 'user', content: message }
            ];

            const response = await fetch('https://api.anthropic.com/v1/messages', {
                method:  'POST',
                headers: {
                    'Content-Type':      'application/json',
                    'anthropic-version': '2023-06-01',
                },
                body: JSON.stringify({
                    model:      'claude-haiku-4-5-20251001',
                    max_tokens:  1024,
                    system:      systemPrompt,
                    messages,
                }),
            });

            if (!response.ok) {
                const err = await response.json().catch(() => ({}));
                if (response.status === 429) {
                    return res.status(429).json({ error: 'AI service temporarily busy. Please try again in a moment.' });
                }
                console.error('[AI] Anthropic error:', response.status, err);
                return res.status(503).json({ error: 'AI service unavailable.' });
            }

            const data  = await response.json();
            const reply = data.content?.[0]?.text || 'No response generated.';

            await log(req, 'ai:chat', { messageLen: message.length });
            res.json({ reply, model: 'claude-haiku', tokensUsed: data.usage?.output_tokens || 0 });

        } catch (e) {
            console.error('[AI] Error:', e.message);
            res.status(503).json({ error: 'AI service error: ' + e.message });
        }
    }
);

app.get('/api/ai/status', auth('view:dashboard'), (req, res) => {
    res.json({
        available:   true,
        model:       'claude-haiku-4-5-20251001',
        provider:    'Anthropic',
        rateLimit:   '20 requests/min per user',
        contextInfo: 'Live blockchain data injected automatically',
    });
});

// ── Security threat reporting ─────────────────────────────────
app.get('/api/admin/security/threats', auth('admin:users'), (req, res) => {
    res.json({
        topThreats:   threatScorer.getAll(),
        anomalyStats: anomalyDetect.getStats(),
        sessions:     sessionBinder.sessions.size,
        checkedAt:    new Date().toISOString(),
    });
});

app.delete('/api/admin/security/threats/:ip', auth('admin:users'), (req, res) => {
    threatScorer.reset(req.params.ip);
    res.json({ ok: true, message: 'Threat score reset for ' + req.params.ip });
});

// ── Error handlers ─────────────────────────────────────────────────────────────
app.use('/api/*', (req, res) => res.status(404).json({ error: 'API endpoint not found' }));
app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large')
        return res.status(413).json({ error: 'Payload too large' });
    console.error('❌ [Server Error]', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// ══════════════════════════════════════════════════════════════
//  STARTUP
// ══════════════════════════════════════════════════════════════
const HTTP_PORT    = NETWORK.HTTP_PORT;
const STRATUM_PORT = NETWORK.STRATUM_PORT;
const P2P_PORT     = NETWORK.P2P_PORT;

async function start() {
    try { await migrate(); }
    catch (e) { console.warn('⚠️  [DB] PostgreSQL unavailable, using in-memory storage:', e.message); }

    bindBlockchain(blockchain, mempool, stratum);

    const server = http.createServer(app);
    server.listen(HTTP_PORT, () => {
        const network = CHAIN_ID === 1 ? 'mainnet' : 'testnet';
        console.log(`
╔══════════════════════════════════════════════╗
║   🚀  ${COIN.NAME} (${COIN.SYMBOL}) Full Node v${COIN.VERSION}        ║
╠══════════════════════════════════════════════╣
║   🌐  HTTP API  : http://localhost:${HTTP_PORT}        ║
║   ⛏️   Stratum  : tcp://localhost:${STRATUM_PORT}      ║
║   🔗  P2P       : tcp://localhost:${P2P_PORT}      ║
║   🌍  Network   : ${network.padEnd(26)} ║
║   📊  Dashboard : http://localhost:${HTTP_PORT}/dashboard ║
║   🔐  Admin     : http://localhost:${HTTP_PORT}/admin.html║
╚══════════════════════════════════════════════╝
        `.trim());
    });

    p2p.listen(P2P_PORT);
    stratum.start(STRATUM_PORT);

    // Connect to seed peers from environment
    const peers = (process.env.PEERS || '').split(',').filter(Boolean);
    peers.forEach(peer =>
        setTimeout(() => p2p.connectToPeer?.(`ws://${peer}`), 3000)
    );

    // Graceful shutdown
    const shutdown = (signal) => {
        console.log(`\n🛑 Received ${signal}. Shutting down gracefully...`);
        server.close(() => {
            p2p.close?.();
            dbPool.end().catch(() => {});
            console.log('✅ Server closed.');
            process.exit(0);
        });
        setTimeout(() => process.exit(1), 10_000);
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT',  () => shutdown('SIGINT'));
}

start().catch(err => {
    console.error('❌ Startup failed:', err);
    process.exit(1);
});

module.exports = app;
