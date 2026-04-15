/**
 * ─────────────────────────────────────────────────────────────
 *  © 2026 MyCoin Project — PROPRIETARY AND CONFIDENTIAL
 *  All Rights Reserved. Unauthorized copying, modification,
 *  distribution, or use of this file is strictly prohibited.
 *  See LICENSE file in the project root for full details.
 * ─────────────────────────────────────────────────────────────
 */
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// ─── Constants ──────────────────────────────────────────────────
const LOCK_FILE   = path.join(__dirname, '../access.lock');
const LOG_FILE    = path.join(__dirname, '../access.log');
const JWT_SECRET  = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ENC_KEY     = process.env.ACCESS_KEY  || crypto.randomBytes(32).toString('hex');
const TOKEN_TTL   = 8 * 60 * 60 * 1000;   // 8 ساعت
const MAX_FAILS   = 5;                      // حداکثر تلاش ناSuccess
const LOCK_TIME   = 15 * 60 * 1000;        // Lock for 15 minutes

// ─── Roles and permissions ──────────────────────────────────────────
const ROLES = {
    admin: {
        label: 'Super Admin',
        color:       '#f5a623',
        permissions: [
            'view:dashboard', 'view:blocks', 'view:transactions', 'view:wallet',
            'view:miners', 'view:logs', 'view:users',
            'mine:blocks', 'mine:transactions',
            'transact:send',
            'admin:users', 'admin:settings', 'admin:apikeys', 'admin:logs'
        ]
    },
    miner: {
        label: 'Miner',
        color:       '#00e676',
        permissions: [
            'view:dashboard', 'view:blocks', 'view:miners',
            'mine:blocks', 'mine:transactions'
        ]
    },
    viewer: {
        label: 'Viewer',
        color:       '#2979ff',
        permissions: [
            'view:dashboard', 'view:blocks', 'view:transactions', 'view:wallet'
        ]
    },
    apikey: {
        label: 'API Key',
        color:       '#c158dc',
        permissions: [
            'view:blocks', 'view:transactions', 'view:stats',
            'transact:send'
        ]
    }
};

// ─── Default users (for first run) ──────────────────────
const DEFAULT_USERS = [
    {
        id:       'admin-001',
        username: 'admin',
        password: 'Admin@1234',   // CHANGE THIS IN PRODUCTION!
        role:     'admin',
        active:   true,
        created:  Date.now()
    },
    {
        id:       'miner-001',
        username: 'miner1',
        password: 'Miner@1234',
        role:     'miner',
        active:   true,
        created:  Date.now()
    },
    {
        id:       'viewer-001',
        username: 'viewer1',
        password: 'Viewer@1234',
        role:     'viewer',
        active:   true,
        created:  Date.now()
    }
];

// ══════════════════════════════════════════════════════════════
//  AES-256-GCM encryption
// ══════════════════════════════════════════════════════════════
function encrypt(text) {
    const key  = crypto.scryptSync(ENC_KEY, 'mycoin-salt', 32);
    const iv   = crypto.randomBytes(16);
    const ciph = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc  = Buffer.concat([ciph.update(text, 'utf8'), ciph.final()]);
    const tag  = ciph.getAuthTag();
    return iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc.toString('hex');
}

function decrypt(data) {
    const [ivHex, tagHex, encHex] = data.split(':');
    const key  = crypto.scryptSync(ENC_KEY, 'mycoin-salt', 32);
    const iv   = Buffer.from(ivHex,  'hex');
    const tag  = Buffer.from(tagHex, 'hex');
    const enc  = Buffer.from(encHex, 'hex');
    const dec  = crypto.createDecipheriv('aes-256-gcm', key, iv);
    dec.setAuthTag(tag);
    return dec.update(enc, undefined, 'utf8') + dec.final('utf8');
}

function hashPassword(password) {
    return crypto.scryptSync(password, 'mycoin-pw-salt', 64).toString('hex');
}

// ══════════════════════════════════════════════════════════════
//  JWT ساده (بدون کتابخانه)
// ══════════════════════════════════════════════════════════════
function signToken(payload) {
    const header  = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body    = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig     = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${parts[0]}.${parts[1]}`).digest('base64url');
    if (sig !== parts[2]) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (Date.now() > payload.exp) return null;
    return payload;
}

// ══════════════════════════════════════════════════════════════
//  فایل access.lock
// ══════════════════════════════════════════════════════════════
function loadLock() {
    try {
        if (!fs.existsSync(LOCK_FILE)) return initLock();
        const raw  = fs.readFileSync(LOCK_FILE, 'utf8');
        return JSON.parse(decrypt(raw));
    } catch {
        return initLock();
    }
}

function saveLock(data) {
    fs.writeFileSync(LOCK_FILE, encrypt(JSON.stringify(data)), 'utf8');
}

function initLock() {
    // hash رمزها برای ذخیره امن
    const users = DEFAULT_USERS.map(u => ({
        ...u,
        passwordHash: hashPassword(u.password),
        password:     undefined,
        apiKeys:      [],
        failCount:    0,
        lockedUntil:  null,
        lastLogin:    null,
        lastIp:       null
    }));

    const data = {
        version:  1,
        created:  Date.now(),
        users,
        apiKeys:  [],
        sessions: []
    };
    saveLock(data);
    console.log('\n🔐 [Access] access.lock created with default users');
    console.log('   ⚠️  Change default passwords immediately!\n');
    return data;
}

// ══════════════════════════════════════════════════════════════
//  لاگ‌گذاری
// ══════════════════════════════════════════════════════════════
function writeLog(entry) {
    const line = JSON.stringify({
        ts:      new Date().toISOString(),
        time:    new Date().toLocaleString('fa-IR'),
        ...entry
    }) + '\n';
    fs.appendFileSync(LOG_FILE, line, 'utf8');
}

function getLogs(limit = 200) {
    try {
        if (!fs.existsSync(LOG_FILE)) return [];
        const lines = fs.readFileSync(LOG_FILE, 'utf8').trim().split('\n').filter(Boolean);
        return lines.slice(-limit).reverse().map(l => JSON.parse(l));
    } catch { return []; }
}

// ══════════════════════════════════════════════════════════════
//  اکشن‌های نام‌گذاری شده برای لاگ
// ══════════════════════════════════════════════════════════════
const ACTION_LABELS = {
    'login':              'Login',
    'logout':             'logout',
    'login:failed':       'login:failed',
    'login:locked':       'Account locked',
    'view:dashboard':     'view:dashboard',
    'view:blocks':        'view:blocks',
    'view:transactions':  'view:transactions',
    'view:wallet':        'view:wallet',
    'view:miners':        'view:miners',
    'view:logs':          'view:logs',
    'mine:transactions':  'mine:transactions',
    'mine:blocks':        'mine:blocks',
    'transact:send':      'Send transaction',
    'admin:users':        'admin User',
    'admin:apikeys':      'admin API Key',
    'admin:settings':     'info',
    'user:created':       'User Create',
    'user:deleted':       'User Delete',
    'user:updated':       'User Edit',
    'apikey:created':     'API Key Create',
    'apikey:revoked':     'API Key Cancel',
    'password:changed':   'password:changed',
    'access:denied':      'Permission denied',
};

// ══════════════════════════════════════════════════════════════
//  کلاس اصلی AccessControl
// ══════════════════════════════════════════════════════════════
class AccessControl {

    constructor() {
        this.data = loadLock();
    }

    // ── login ────────────────────────────────────────────────────
    login({ username, password, ip = 'unknown' }) {
        const user = this.data.users.find(u => u.username === username);

        if (!user || !user.active) {
            writeLog({ action: 'login:failed', username, ip, reason: 'user not found' });
            return { ok: false, error: 'User' };
        }

        // Check قفل بودن
        if (user.lockedUntil && Date.now() < user.lockedUntil) {
            const rem = Math.ceil((user.lockedUntil - Date.now()) / 60000);
            writeLog({ action: 'login:locked', username, ip });
            return { ok: false, error: `Account is locked. ${rem}  دیگر تلاش کنید` };
        }

        // Check رمز
        const hash = hashPassword(password);
        if (hash !== user.passwordHash) {
            user.failCount = (user.failCount || 0) + 1;
            if (user.failCount >= MAX_FAILS) {
                user.lockedUntil = Date.now() + LOCK_TIME;
                writeLog({ action: 'login:locked', username, ip, fails: user.failCount });
            } else {
                writeLog({ action: 'login:failed', username, ip, fails: user.failCount });
            }
            saveLock(this.data);
            return { ok: false, error: ` اشتباه است (${user.failCount}/${MAX_FAILS})` };
        }

        // login Success
        user.failCount   = 0;
        user.lockedUntil = null;
        user.lastLogin   = Date.now();
        user.lastIp      = ip;

        const payload = {
            id:       user.id,
            username: user.username,
            role:     user.role,
            iat:      Date.now(),
            exp:      Date.now() + TOKEN_TTL
        };
        const token = signToken(payload);

        // ذخیره session
        this.data.sessions = (this.data.sessions || []).filter(s => s.userId !== user.id);
        this.data.sessions.push({ token, userId: user.id, ip, loginAt: Date.now() });

        saveLock(this.data);
        writeLog({ action: 'login', username, role: user.role, ip });

        return {
            ok:    true,
            token,
            user:  { id: user.id, username: user.username, role: user.role, label: ROLES[user.role]?.label }
        };
    }

    // ── Exit ────────────────────────────────────────────────────
    logout(token, ip = 'unknown') {
        const payload = verifyToken(token);
        this.data.sessions = (this.data.sessions || []).filter(s => s.token !== token);
        saveLock(this.data);
        if (payload) writeLog({ action: 'logout', username: payload.username, role: payload.role, ip });
        return { ok: true };
    }

    // ── Confirm Token ─────────────────────────────────────────────
    authenticate(token) {
        const payload = verifyToken(token);
        if (!payload) return null;
        const user = this.data.users.find(u => u.id === payload.id);
        if (!user || !user.active) return null;
        return { ...payload, permissions: ROLES[payload.role]?.permissions || [] };
    }

    // ── Confirm API Key ────────────────────────────────────────────
    authenticateApiKey(key) {
        const entry = this.data.apiKeys?.find(k => k.key === key && k.active);
        if (!entry) return null;
        entry.lastUsed = Date.now();
        entry.useCount = (entry.useCount || 0) + 1;
        saveLock(this.data);
        return {
            id:          entry.id,
            username:    entry.name,
            role:        'apikey',
            permissions: ROLES.apikey.permissions
        };
    }

    // ── Check مجوز ──────────────────────────────────────────────
    can(user, permission) {
        return user?.permissions?.includes(permission) || false;
    }

    // ── Middleware برای Express ──────────────────────────────────
    middleware(permission = null) {
        return (req, res, next) => {
            // Check API Key در header
            const apiKey = req.headers['x-api-key'];
            if (apiKey) {
                const user = this.authenticateApiKey(apiKey);
                if (user) {
                    req.user = user;
                    if (permission && !this.can(user, permission)) {
                        writeLog({ action: 'access:denied', username: user.username, permission, ip: req.ip, path: req.path });
                        return res.status(403).json({ error: 'Permission denied', required: permission });
                    }
                    return next();
                }
            }

            // Check JWT Token
            const auth  = req.headers['authorization'] || '';
            const token = auth.startsWith('Bearer ') ? auth.slice(7) : req.cookies?.token;

            const user = this.authenticate(token);
            if (!user) {
                return res.status(401).json({ error: 'info', code: 'UNAUTHORIZED' });
            }

            req.user = user;

            if (permission && !this.can(user, permission)) {
                writeLog({ action: 'access:denied', username: user.username, role: user.role, permission, ip: req.ip, path: req.path });
                return res.status(403).json({ error: 'Permission denied', required: permission });
            }

            next();
        };
    }

    // ── Operation log ──────────────────────────────────────────────
    log(req, action, details = {}) {
        if (!req.user) return;
        writeLog({
            action,
            label:    ACTION_LABELS[action] || action,
            username: req.user.username,
            role:     req.user.role,
            ip:       req.ip || req.connection?.remoteAddress || 'unknown',
            path:     req.path,
            method:   req.method,
            ...details
        });
    }

    // ── مدیریت Userان ──────────────────────────────────────────
    getUsers() {
        return this.data.users.map(u => ({
            id:          u.id,
            username:    u.username,
            role:        u.role,
            roleLabel:   ROLES[u.role]?.label,
            active:      u.active,
            created:     u.created,
            lastLogin:   u.lastLogin,
            lastIp:      u.lastIp,
            failCount:   u.failCount || 0,
            lockedUntil: u.lockedUntil,
            isLocked:    u.lockedUntil && Date.now() < u.lockedUntil
        }));
    }

    createUser({ username, password, role }, creatorUsername) {
        if (this.data.users.find(u => u.username === username))
            return { ok: false, error: 'User' };
        if (!ROLES[role])
            return { ok: false, error: 'role Invalid' };

        const user = {
            id:           `${role}-${Date.now()}`,
            username,
            passwordHash: hashPassword(password),
            role,
            active:       true,
            created:      Date.now(),
            failCount:    0,
            lockedUntil:  null,
            lastLogin:    null,
            lastIp:       null
        };
        this.data.users.push(user);
        saveLock(this.data);
        writeLog({ action: 'user:created', username: creatorUsername, target: username, role });
        return { ok: true, user: { id: user.id, username, role } };
    }

    updateUser(id, updates, editorUsername) {
        const user = this.data.users.find(u => u.id === id);
        if (!user) return { ok: false, error: 'User Not found' };

        if (updates.password) {
            user.passwordHash = hashPassword(updates.password);
            writeLog({ action: 'password:changed', username: editorUsername, target: user.username });
        }
        if (updates.role)   { user.role   = updates.role;   }
        if (updates.active !== undefined) { user.active = updates.active; }
        if (updates.unlock) { user.failCount = 0; user.lockedUntil = null; }

        saveLock(this.data);
        writeLog({ action: 'user:updated', username: editorUsername, target: user.username, updates: Object.keys(updates) });
        return { ok: true };
    }

    deleteUser(id, deleterUsername) {
        const idx = this.data.users.findIndex(u => u.id === id);
        if (idx === -1) return { ok: false, error: 'User Not found' };
        const [removed] = this.data.users.splice(idx, 1);
        saveLock(this.data);
        writeLog({ action: 'user:deleted', username: deleterUsername, target: removed.username });
        return { ok: true };
    }

    // ── مدیریت API Key ───────────────────────────────────────────
    getApiKeys() {
        return (this.data.apiKeys || []).map(k => ({
            id:        k.id,
            name:      k.name,
            key:       k.key.substring(0, 8) + '...',  // نمایش جزئی
            active:    k.active,
            created:   k.created,
            lastUsed:  k.lastUsed,
            useCount:  k.useCount || 0
        }));
    }

    createApiKey({ name }, creatorUsername) {
        const key = 'myc_' + crypto.randomBytes(24).toString('hex');
        const entry = {
            id:       `key-${Date.now()}`,
            name,
            key,
            active:   true,
            created:  Date.now(),
            lastUsed: null,
            useCount: 0
        };
        if (!this.data.apiKeys) this.data.apiKeys = [];
        this.data.apiKeys.push(entry);
        saveLock(this.data);
        writeLog({ action: 'apikey:created', username: creatorUsername, keyName: name });
        return { ok: true, key };  // کلید کامل فقط یک‌بار نمایش داده می‌شود
    }

    revokeApiKey(id, revokerUsername) {
        const key = (this.data.apiKeys || []).find(k => k.id === id);
        if (!key) return { ok: false, error: 'Not found' };
        key.active = false;
        saveLock(this.data);
        writeLog({ action: 'apikey:revoked', username: revokerUsername, keyName: key.name });
        return { ok: true };
    }

    // ── لاگ‌ها ──────────────────────────────────────────────────
    getLogs(limit = 200, filter = {}) {
        let logs = getLogs(limit * 2);
        if (filter.username) logs = logs.filter(l => l.username === filter.username);
        if (filter.action)   logs = logs.filter(l => l.action?.startsWith(filter.action));
        if (filter.role)     logs = logs.filter(l => l.role === filter.role);
        return logs.slice(0, limit);
    }

    // ── اطلاعات role‌ها ───────────────────────────────────────────
    getRoles() { return ROLES; }
}

// singleton
const ac = new AccessControl();
module.exports = { ac, ROLES, ACTION_LABELS };

// ── Methodهای اضافه برای سازگاری با server.js ──────────────────
AccessControl.prototype.getUserById = function(id) {
    const u = (this.data.users || []).find(u => u.id === id);
    if (!u) return null;
    return { id: u.id, username: u.username, role: u.role, permissions: (ROLES[u.role]?.permissions || []) };
};

AccessControl.prototype.hasPerm = function(user, perm) {
    if (!user || !perm) return true;
    const u = (this.data.users || []).find(u => u.id === user.id);
    if (!u) return false;
    const perms = ROLES[u.role]?.permissions || [];
    return perms.includes(perm);
};
