/**
 * ─────────────────────────────────────────────────────────────
 *  © 2026 MyCoin Project — PROPRIETARY AND CONFIDENTIAL
 *  All Rights Reserved. Unauthorized copying, modification,
 *  distribution, or use of this file is strictly prohibited.
 *  See LICENSE file in the project root for full details.
 * ─────────────────────────────────────────────────────────────
 */
// ════════════════════════════════════════════════════════════
//  🛡️ Rate Limiter + DDoS Protection
//  ویژگی‌ها: Sliding Window، IP Blocking، Slowdown، Honeypot
// ════════════════════════════════════════════════════════════

// ── Sliding Window Rate Limiter ─────────────────────────────
class SlidingWindowLimiter {
    constructor({ windowMs, max, message, keyPrefix = '' }) {
        this.windowMs  = windowMs;
        this.max       = max;
        this.message   = message || 'Too many requests';
        this.keyPrefix = keyPrefix;
        this.store     = new Map(); // در production از Redis استفاده کنید
    }

    _getKey(req) {
        const ip = this._getIP(req);
        return `${this.keyPrefix}:${ip}`;
    }

    _getIP(req) {
        return (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    }

    _clean(record) {
        const cutoff = Date.now() - this.windowMs;
        record.hits  = record.hits.filter(t => t > cutoff);
    }

    check(req) {
        const key = this._getKey(req);
        if (!this.store.has(key)) this.store.set(key, { hits: [] });
        const record = this.store.get(key);
        this._clean(record);

        const remaining = Math.max(0, this.max - record.hits.length);
        const resetAt   = record.hits.length > 0
            ? record.hits[0] + this.windowMs
            : Date.now() + this.windowMs;

        if (record.hits.length >= this.max) {
            return { allowed: false, remaining: 0, resetAt };
        }

        record.hits.push(Date.now());
        return { allowed: true, remaining: remaining - 1, resetAt };
    }

    middleware() {
        return (req, res, next) => {
            const result = this.check(req);
            res.setHeader('X-RateLimit-Limit',     this.max);
            res.setHeader('X-RateLimit-Remaining', result.remaining);
            res.setHeader('X-RateLimit-Reset',     Math.ceil(result.resetAt / 1000));

            if (!result.allowed) {
                res.setHeader('Retry-After', Math.ceil(this.windowMs / 1000));
                return res.status(429).json({
                    error:   this.message,
                    retryAfter: Math.ceil((result.resetAt - Date.now()) / 1000)
                });
            }
            next();
        };
    }
}

// ── DDoS Protection ─────────────────────────────────────────
class DDoSProtection {
    constructor() {
        this.ipStore    = new Map();  // آمار هر IP
        this.blocklist  = new Map();  // IP های block شده: ip → unblockAt
        this.whitelist  = new Set((process.env.IP_WHITELIST || '127.0.0.1,::1').split(','));

        // تنظیمات DDoS
        this.cfg = {
            reqPerSec:      parseInt(process.env.DDOS_REQ_PER_SEC)     || 50,
            blockThreshold: parseInt(process.env.DDOS_BLOCK_THRESHOLD)  || 200,
            blockDuration:  parseInt(process.env.DDOS_BLOCK_DURATION)   || 15 * 60_000,  // 15 دقیقه
            windowMs:       1000,   // پنجره 1 ثانیه
        };

        // پاکسازی خودکار
        setInterval(() => this._cleanup(), 30_000);
    }

    _getIP(req) {
        return (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    }

    _cleanup() {
        const now = Date.now();
        for (const [ip, until] of this.blocklist) {
            if (now > until) this.blocklist.delete(ip);
        }
        for (const [ip, data] of this.ipStore) {
            if (now - data.lastSeen > 60_000) this.ipStore.delete(ip);
        }
    }

    _getRecord(ip) {
        if (!this.ipStore.has(ip)) {
            this.ipStore.set(ip, { hits: 0, windowStart: Date.now(), lastSeen: Date.now(), suspicious: 0 });
        }
        return this.ipStore.get(ip);
    }

    check(req) {
        const ip = this._getIP(req);

        // Whitelist
        if (this.whitelist.has(ip)) return { allowed: true, blocked: false };

        // بررسی block بودن
        if (this.blocklist.has(ip)) {
            const until = this.blocklist.get(ip);
            if (Date.now() < until) {
                return { allowed: false, blocked: true, until };
            }
            this.blocklist.delete(ip);
        }

        const record  = this._getRecord(ip);
        const now     = Date.now();
        record.lastSeen = now;

        // ریست پنجره
        if (now - record.windowStart > this.cfg.windowMs) {
            record.hits        = 0;
            record.windowStart = now;
        }

        record.hits++;

        // بررسی headers مشکوک
        const ua = req.headers['user-agent'] || '';
        if (!ua || ua.length < 5) record.suspicious += 2;
        if (!req.headers['accept']) record.suspicious += 1;

        // block کردن
        if (record.hits >= this.cfg.blockThreshold || record.suspicious >= 10) {
            this.blocklist.set(ip, now + this.cfg.blockDuration);
            console.warn(`🚫 [DDoS] IP block : ${ip} | hits=${record.hits} suspicious=${record.suspicious}`);
            return { allowed: false, blocked: true, until: now + this.cfg.blockDuration };
        }

        // Throttle
        if (record.hits >= this.cfg.reqPerSec) {
            return { allowed: false, blocked: false, throttled: true };
        }

        return { allowed: true };
    }

    blockIP(ip, durationMs = null) {
        this.blocklist.set(ip, Date.now() + (durationMs || this.cfg.blockDuration));
    }

    unblockIP(ip) {
        this.blocklist.delete(ip);
    }

    middleware() {
        return (req, res, next) => {
            const result = this.check(req);

            if (!result.allowed) {
                if (result.blocked) {
                    return res.status(403).json({
                        error: 'IP',
                        until: result.until
                    });
                }
                return res.status(429).json({ error: 'Too many requests' });
            }
            next();
        };
    }

    getStats() {
        return {
            blocked: this.blocklist.size,
            tracked: this.ipStore.size,
            blockedIPs: [...this.blocklist.entries()].map(([ip, until]) => ({ ip, until: new Date(until) }))
        };
    }
}

// ── Honeypot middleware (تله برای بات‌ها) ──────────────────
function honeypot() {
    const traps  = ['/admin.php', '/wp-admin', '/.env', '/phpinfo.php', '/login.php'];
    const caught = new Map();

    return (req, res, next) => {
        const path = req.path.toLowerCase();
        if (traps.some(t => path.startsWith(t))) {
            const ip = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
            caught.set(ip, (caught.get(ip) || 0) + 1);
            console.warn(`🍯 [Honeypot] ${ip} → ${req.path}`);
            // پاسخ تأخیردار برای مصرف منابع بات
            setTimeout(() => res.status(404).json({ error: 'Not Found' }), 2000);
            return;
        }
        next();
    };
}

// ── نمونه‌های آماده ─────────────────────────────────────────
const ddos = new DDoSProtection();

const limiters = {
    global:  new SlidingWindowLimiter({ windowMs: 60_000,   max: parseInt(process.env.RATE_GLOBAL)  || 300,  keyPrefix: 'gl',    message: 'limit' }),
    auth:    new SlidingWindowLimiter({ windowMs: 15 * 60_000, max: parseInt(process.env.RATE_AUTH) || 10,   keyPrefix: 'auth',  message: 'Login —' }),
    api:     new SlidingWindowLimiter({ windowMs: 60_000,   max: parseInt(process.env.RATE_API)     || 100,  keyPrefix: 'api',   message: 'limit API' }),
    mining:  new SlidingWindowLimiter({ windowMs: 60_000,   max: parseInt(process.env.RATE_MINE)    || 30,   keyPrefix: 'mine',  message: 'limit mining' }),
    stratum: new SlidingWindowLimiter({ windowMs: 60_000,   max: parseInt(process.env.RATE_STRATUM) || 60,   keyPrefix: 'str',   message: 'limit Stratum' }),
};

module.exports = { SlidingWindowLimiter, DDoSProtection, honeypot, ddos, limiters };
