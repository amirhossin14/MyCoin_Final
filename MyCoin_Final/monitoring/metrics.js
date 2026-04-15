/**
 * ─────────────────────────────────────────────────────────────
 *  © 2026 MyCoin Project — PROPRIETARY AND CONFIDENTIAL
 *  All Rights Reserved. Unauthorized copying, modification,
 *  distribution, or use of this file is strictly prohibited.
 *  See LICENSE file in the project root for full details.
 * ─────────────────────────────────────────────────────────────
 */
// ════════════════════════════════════════════════════════════
//  📊 Prometheus Metrics Exporter
//  ویژگی‌ها: HTTP Metrics، Blockchain Metrics، System Metrics
// ════════════════════════════════════════════════════════════
const os = require('os');

// ── Counter & Gauge helpers (بدون dependency خارجی) ─────────
class Counter {
    constructor(name, help, labels = []) {
        this.name   = name;
        this.help   = help;
        this.labels = labels;
        this.values = new Map();
    }
    inc(labelVals = {}, amount = 1) {
        const key = JSON.stringify(labelVals);
        this.values.set(key, { labels: labelVals, value: (this.values.get(key)?.value || 0) + amount });
    }
    render() {
        let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} counter\n`;
        for (const { labels, value } of this.values.values()) {
            const lstr = Object.entries(labels).map(([k, v]) => `${k}="${v}"`).join(',');
            out += `${this.name}${lstr ? '{' + lstr + '}' : ''} ${value}\n`;
        }
        return out;
    }
}

class Gauge {
    constructor(name, help, labels = []) {
        this.name   = name;
        this.help   = help;
        this.labels = labels;
        this.values = new Map();
        this._fn    = null;
    }
    set(labelVals, value) {
        const key = typeof labelVals === 'number' ? '{}' : JSON.stringify(labelVals);
        const lv  = typeof labelVals === 'number' ? {} : labelVals;
        const val = typeof labelVals === 'number' ? labelVals : value;
        this.values.set(key, { labels: lv, value: val });
    }
    collect(fn) { this._fn = fn; }
    render() {
        if (this._fn) this._fn(this);
        let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} gauge\n`;
        for (const { labels, value } of this.values.values()) {
            const lstr = Object.entries(labels).map(([k, v]) => `${k}="${v}"`).join(',');
            out += `${this.name}${lstr ? '{' + lstr + '}' : ''} ${value}\n`;
        }
        return out;
    }
}

class Histogram {
    constructor(name, help, buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5]) {
        this.name    = name;
        this.help    = help;
        this.buckets = buckets;
        this.reset();
    }
    reset() {
        this.counts = new Array(this.buckets.length).fill(0);
        this.sum    = 0;
        this.total  = 0;
    }
    observe(value) {
        this.sum += value;
        this.total++;
        for (let i = 0; i < this.buckets.length; i++) {
            if (value <= this.buckets[i]) this.counts[i]++;
        }
    }
    render() {
        let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} histogram\n`;
        for (let i = 0; i < this.buckets.length; i++) {
            out += `${this.name}_bucket{le="${this.buckets[i]}"} ${this.counts[i]}\n`;
        }
        out += `${this.name}_bucket{le="+Inf"} ${this.total}\n`;
        out += `${this.name}_sum ${this.sum}\n`;
        out += `${this.name}_count ${this.total}\n`;
        return out;
    }
}

// ════════════════════════════════════════════════════════════
//  تعریف متریک‌ها
// ════════════════════════════════════════════════════════════
const metrics = {
    // HTTP
    httpRequests:  new Counter('mycoin_http_requests_total', 'Total HTTP requests', ['method', 'route', 'status']),
    httpDuration:  new Histogram('mycoin_http_duration_seconds', 'time HTTP'),
    httpActive:    new Gauge('mycoin_http_active_connections', 'connection active HTTP'),

    // Auth
    loginTotal:    new Counter('mycoin_auth_login_total', 'count Login', ['result']),
    activeSessions:new Gauge('mycoin_auth_active_sessions', 'count active'),

    // Rate Limit / DDoS
    rateLimited:   new Counter('mycoin_rate_limited_total', 'info', ['limiter']),
    ddosBlocked:   new Counter('mycoin_ddos_blocked_total', 'IP block DDoS'),
    blockedIPs:    new Gauge('mycoin_ddos_blocked_ips', 'count IP block'),

    // Blockchain
    blockHeight:   new Gauge('mycoin_blockchain_height', 'height block'),
    blockDifficulty:new Gauge('mycoin_blockchain_difficulty', 'difficulty'),
    mempoolSize:   new Gauge('mycoin_mempool_transactions', 'count transaction mempool'),
    blockMined:    new Counter('mycoin_blocks_mined_total', 'block mining', ['miner']),
    hashrate:      new Gauge('mycoin_hashrate_estimate', 'hash network'),

    // Stratum
    stratumMiners: new Gauge('mycoin_stratum_miners_connected', 'miner Connected'),
    stratumShares: new Counter('mycoin_stratum_shares_total', 'send', ['result']),

    // System
    nodeMemory:    new Gauge('mycoin_node_memory_bytes', 'memory Node.js', ['type']),
    nodeCPU:       new Gauge('mycoin_node_cpu_seconds', 'CPU Node.js', ['type']),
    uptime:        new Gauge('mycoin_uptime_seconds', 'server'),
    osLoad:        new Gauge('mycoin_os_load_average', 'average CPU', ['period']),

    // DB
    dbPoolActive:  new Gauge('mycoin_db_pool_active', 'connection active DB'),
    dbPoolWaiting: new Gauge('mycoin_db_pool_waiting', 'DB'),
    dbQueryDuration:new Histogram('mycoin_db_query_seconds', 'time DB'),

    // KYC
    kycSubmissions:new Counter('mycoin_kyc_submissions_total', 'KYC', ['status']),
    kycPending:    new Gauge('mycoin_kyc_pending', 'KYC pending review'),
};

// ════════════════════════════════════════════════════════════
//  Middleware HTTP
// ════════════════════════════════════════════════════════════
let _activeConnections = 0;

function httpMetricsMiddleware(req, res, next) {
    const start = process.hrtime.bigint();
    _activeConnections++;
    metrics.httpActive.set(_activeConnections);

    res.on('finish', () => {
        _activeConnections--;
        metrics.httpActive.set(_activeConnections);

        const dur  = Number(process.hrtime.bigint() - start) / 1e9;
        const route = req.route?.path || req.path || 'unknown';

        metrics.httpRequests.inc({ method: req.method, route, status: res.statusCode });
        metrics.httpDuration.observe(dur);
    });

    next();
}

// ════════════════════════════════════════════════════════════
//  Collect System Metrics
// ════════════════════════════════════════════════════════════
function collectSystemMetrics() {
    // Memory
    const mem = process.memoryUsage();
    metrics.nodeMemory.set({ type: 'heapUsed' },  mem.heapUsed);
    metrics.nodeMemory.set({ type: 'heapTotal' }, mem.heapTotal);
    metrics.nodeMemory.set({ type: 'rss' },        mem.rss);
    metrics.nodeMemory.set({ type: 'external' },   mem.external);

    // CPU
    const cpu = process.cpuUsage();
    metrics.nodeCPU.set({ type: 'user' },   cpu.user / 1e6);
    metrics.nodeCPU.set({ type: 'system' }, cpu.system / 1e6);

    // Uptime & Load
    metrics.uptime.set(process.uptime());
    const load = os.loadavg();
    metrics.osLoad.set({ period: '1m' },  load[0]);
    metrics.osLoad.set({ period: '5m' },  load[1]);
    metrics.osLoad.set({ period: '15m' }, load[2]);
}

// ════════════════════════════════════════════════════════════
//  /metrics endpoint handler
// ════════════════════════════════════════════════════════════
function metricsHandler(req, res) {
    collectSystemMetrics();

    const output = Object.values(metrics)
        .map(m => m.render())
        .join('\n');

    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(output);
}

// ── Blockchain updater ──────────────────────────────────────
function bindBlockchain(blockchain, transactionPool, stratumServer) {
    setInterval(() => {
        metrics.blockHeight.set(blockchain.chain.length - 1);
        metrics.blockDifficulty.set(blockchain.chain[blockchain.chain.length - 1]?.difficulty || 0);
        metrics.mempoolSize.set(Object.keys(transactionPool.transactionMap || {}).length);

        if (stratumServer) {
            metrics.stratumMiners.set(stratumServer.getMiners?.()?.length || 0);
        }
    }, 5000);
}

module.exports = { metrics, httpMetricsMiddleware, metricsHandler, bindBlockchain };
