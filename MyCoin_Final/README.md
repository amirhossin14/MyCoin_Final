# MyCoin Node v4.0

A production-grade, Bitcoin-inspired blockchain built in Node.js — fully in English.

## Features

| Category | Details |
|---|---|
| **Consensus** | Proof of Work (SHA-256d), difficulty adjusts every 2016 blocks |
| **Transactions** | UTXO model, secp256k1 signatures, double-spend protection |
| **Mining** | Block halving every 210,000 blocks, coinbase maturity (100 blocks) |
| **Mempool** | Fee-rate ordering, duplicate & replay detection, 72h expiry |
| **P2P** | TCP peer network, block/tx propagation, chain sync |
| **Stratum** | Mining pool protocol (Vardiff, worker ban) |
| **Security** | JWT + Refresh tokens, 2FA (TOTP), DDoS protection, IP ban, honeypot |
| **Database** | PostgreSQL (optional, falls back to in-memory) |
| **Monitoring** | Prometheus metrics, audit logs |
| **Explorer** | Public block/tx/address explorer (no login required) |
| **Admin** | Full admin panel with 2FA at `/admin.html` |

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env
# Edit .env — at minimum set JWT_SECRET and ACCESS_KEY

# 3. Start the node
npm start

# 4. Open in browser
# API:     http://localhost:3000/api/health
# Explorer: http://localhost:3000/tx.html
# Admin:    http://localhost:3000/admin.html
```

## Default Credentials

```
Username: admin
Password: Admin@1234
```

> ⚠️ **Change the default password immediately after first login!**

## API Endpoints

### Public (no auth required)

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Node health check |
| GET | `/api/coin-info` | Coin metadata |
| GET | `/api/stats` | Network statistics |
| GET | `/api/blocks` | Block list (paginated) |
| GET | `/api/block/:ref` | Block by height or hash |
| GET | `/api/tx/:txid` | Transaction details |
| GET | `/api/address/:addr` | Address balance & UTXOs |
| GET | `/api/search/:q` | Search by hash/height/address |

### Authenticated

| Method | Path | Permission |
|---|---|---|
| POST | `/api/auth/login` | Public |
| POST | `/api/auth/logout` | Any |
| GET  | `/api/auth/me` | Any |
| POST | `/api/auth/2fa/setup` | Any |
| POST | `/api/auth/2fa/confirm` | Any |
| POST | `/api/transact` | `transact:send` |
| POST | `/api/mine` | `mine:blocks` |
| GET  | `/api/mempool` | `view:transactions` |
| GET  | `/api/admin/users` | `admin:users` |
| GET  | `/api/admin/logs` | `admin:logs` |
| GET  | `/api/admin/chain/validate` | `admin:users` |

## Environment Variables

See `.env.example` for all options.

Key variables:
- `PORT` — HTTP port (default: 3000)
- `CHAIN_ID` — 1 for mainnet, 3 for testnet
- `JWT_SECRET` — Secret for JWT signing (required in production)
- `DATABASE_URL` — PostgreSQL connection string (optional)
- `PEERS` — Comma-separated seed node addresses

## Project Structure

```
mycoin-node/
├── blockchain/
│   ├── blockchain.js   # Block, chain, PoW, reorg, difficulty
│   └── crypto.js       # SHA-256d, secp256k1, Merkle tree
├── utxo/
│   └── utxo.js         # UTXO set, Transaction builder
├── wallet/
│   └── wallet.js       # Key management, tx signing
├── mempool/
│   └── mempool.js      # Transaction pool
├── p2p/
│   └── p2p.js          # Peer-to-peer network
├── mining-pool/
│   └── stratum.js      # Stratum mining protocol
├── middleware/
│   ├── jwt.js          # JWT authentication
│   └── ratelimit.js    # Rate limiting, DDoS, honeypot
├── monitoring/
│   └── metrics.js      # Prometheus metrics
├── db/
│   └── database.js     # PostgreSQL + in-memory fallback
├── app/
│   └── access-control.js  # Users, roles, TOTP/2FA
├── public/
│   ├── admin.html      # Admin panel (requires login)
│   ├── tx.html         # Transaction explorer (public)
│   └── send.html       # Send MYC (requires login)
├── config.js           # All configuration
├── server.js           # Express server + all API routes
└── package.json
```

## Docker

```bash
cd docker
docker-compose up -d
```

---

## ⚖️ License & Legal

**Copyright © 2026 MyCoin Project. All Rights Reserved.**

This software is **proprietary and confidential**. Unauthorized copying, modification,
distribution, or use of this software, via any medium, is **strictly prohibited**.

See the [LICENSE](./LICENSE) file for full terms.

For licensing inquiries: legal@mycoin.example.com

---

## ⚖️ License & Legal

**Copyright © 2026 MyCoin Project. All Rights Reserved.**

This software is **proprietary and confidential**. Unauthorized copying, modification,
distribution, or use of this software, via any medium, is **strictly prohibited**.

See the [LICENSE](./LICENSE) file for full terms.

For licensing inquiries: legal@mycoin.example.com
