/**
 * ─────────────────────────────────────────────────────────────
 *  © 2026 MyCoin Project — PROPRIETARY AND CONFIDENTIAL
 *  All Rights Reserved. Unauthorized copying, modification,
 *  distribution, or use of this file is strictly prohibited.
 *  See LICENSE file in the project root for full details.
 * ─────────────────────────────────────────────────────────────
 */
// ════════════════════════════════════════════════════════════
//  🔑 JWT Authentication Middleware
//  ویژگی‌ها: Access Token + Refresh Token + Blacklist
// ════════════════════════════════════════════════════════════
const crypto = require('crypto');

// ── تنظیمات ────────────────────────────────────────────────
const JWT_SECRET        = process.env.JWT_SECRET  || crypto.randomBytes(64).toString('hex');
const JWT_REFRESH_SECRET= process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
const ACCESS_TTL        = parseInt(process.env.JWT_ACCESS_TTL)  || 15 * 60;        // 15 دقیقه
const REFRESH_TTL       = parseInt(process.env.JWT_REFRESH_TTL) || 7 * 24 * 3600;  // 7 روز

// ── Blacklist (در production از Redis استفاده کنید) ─────────
const blacklist = new Set();
setInterval(() => {
    // پاکسازی خودکار توکن‌های منقضی
    const now = Math.floor(Date.now() / 1000);
    for (const t of blacklist) {
        try {
            const payload = _decode(t);
            if (payload.exp < now) blacklist.delete(t);
        } catch { blacklist.delete(t); }
    }
}, 60_000);

// ── Base64url helpers ───────────────────────────────────────
const b64e = s => Buffer.from(s).toString('base64url');
const b64d = s => Buffer.from(s, 'base64url').toString('utf8');

function _sign(payload, secret) {
    const header = b64e(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const body   = b64e(JSON.stringify(payload));
    const sig    = crypto.createHmac('sha256', secret)
        .update(`${header}.${body}`).digest('base64url');
    return `${header}.${body}.${sig}`;
}

function _verify(token, secret) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('invalid_token');
    const [header, body, sig] = parts;
    const expected = crypto.createHmac('sha256', secret)
        .update(`${header}.${body}`).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)))
        throw new Error('invalid_signature');
    const payload = JSON.parse(b64d(body));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000))
        throw new Error('token_expired');
    return payload;
}

function _decode(token) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('invalid_token');
    return JSON.parse(b64d(parts[1]));
}

// ════════════════════════════════════════════════════════════
//  توابع اصلی
// ════════════════════════════════════════════════════════════
function createTokens(user) {
    const now = Math.floor(Date.now() / 1000);
    const accessPayload = {
        sub:  user.id,
        user: { id: user.id, username: user.username, role: user.role },
        iat:  now,
        exp:  now + ACCESS_TTL,
        type: 'access'
    };
    const refreshPayload = {
        sub:  user.id,
        jti:  crypto.randomBytes(16).toString('hex'),  // یکتا برای هر refresh
        iat:  now,
        exp:  now + REFRESH_TTL,
        type: 'refresh'
    };
    return {
        accessToken:  _sign(accessPayload,  JWT_SECRET),
        refreshToken: _sign(refreshPayload, JWT_REFRESH_SECRET),
        expiresIn:    ACCESS_TTL
    };
}

function verifyAccess(token) {
    if (blacklist.has(token)) throw new Error('token_revoked');
    return _verify(token, JWT_SECRET);
}

function verifyRefresh(token) {
    if (blacklist.has(token)) throw new Error('token_revoked');
    return _verify(token, JWT_REFRESH_SECRET);
}

function revokeToken(token) {
    blacklist.add(token);
}

// ── Express Middleware ──────────────────────────────────────
function jwtMiddleware(required = true) {
    return (req, res, next) => {
        const auth  = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;

        if (!token) {
            if (!required) return next();
            return res.status(401).json({ error: 'Token not provided' });
        }

        try {
            const payload = verifyAccess(token);
            req.user      = payload.user;
            req.jwtToken  = token;
            next();
        } catch (e) {
            const code = e.message === 'token_expired' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN';
            return res.status(401).json({ error: e.message, code });
        }
    };
}

module.exports = { createTokens, verifyAccess, verifyRefresh, revokeToken, jwtMiddleware, ACCESS_TTL, REFRESH_TTL };
