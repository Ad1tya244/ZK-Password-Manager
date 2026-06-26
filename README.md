# Zero-Knowledge Password Manager

A security-first, monorepo password manager implementing a **zero-knowledge cryptographic architecture** — the server is treated as completely untrusted. All vault encryption, key derivation, and recovery operations are performed entirely client-side using the native Web Crypto API. The backend never handles plaintext credentials, master passwords, or raw key material.

---

## System Architecture

Managed by [TurboRepo](https://turbo.build/), this monorepo co-locates the Next.js 14 frontend and its API Route Handlers in a single deployable package.

```
zk-password-manager/
├── apps/
│   ├── web/                        # Next.js 14 (App Router) — UI + co-located API Route Handlers
│   │   └── src/
│   │       ├── app/api/            # Route Handlers (auth/*, vault/*)
│   │       ├── components/         # VaultDashboard, AuthForm, RecoverySetup
│   │       ├── lib/                # server-auth, validation, rate-limit, services
│   │       └── utils/              # encryption.utils, password-strength
│   └── api/                        # Standalone API server (development)
├── packages/
│   ├── crypto/                     # Client-side Web Crypto wrappers (PBKDF2, AES-GCM, HKDF)
│   ├── database/                   # Prisma ORM schema + singleton client
│   └── shared/                     # Zod validation schemas + shared TypeScript types
├── package.json                    # Monorepo root
└── turbo.json                      # Turbo pipeline configuration
```

---

## Security Model & Cryptographic Primitives

### 1. Key Derivation — Dual-Key Wrapped Architecture

| Key | Derivation | Purpose |
|-----|-----------|---------|
| **KEK** (Key Encryption Key) | PBKDF2-HMAC-SHA256, 100k iterations, unique `vaultSalt` | Wraps/unwraps the VEK; never sent to server |
| **VEK** (Vault Encryption Key) | 256-bit random AES key generated at registration | Encrypts all vault items (AES-GCM 256-bit) |
| **Recovery KEK** | HKDF-SHA256 from 256-bit recovery key | Wraps a copy of the VEK for account recovery |

Changing the master password only requires re-wrapping the VEK — vault item ciphertexts are untouched.

### 2. Authentication
- Client sends only the **authentication hash** (PBKDF2 output), never the raw master password.
- Server re-hashes it with **Argon2id** before storing or comparing.

### 3. Session Management
- Database-backed `Session` table stores SHA-256 hashes of JWT access tokens.
- Every authenticated request verifies **both** the JWT signature **and** an active session record.
- Sessions are revoked on: logout, logout-all, master password change, account recovery, 2FA reconfiguration, and account deletion (cascade).
- Duplicate sessions for the same device are prevented during login.
- Expired sessions are cleaned up automatically during authentication.
- Device information (browser + OS) is parsed from the User-Agent at session creation and stored directly — not re-parsed on every retrieval.

### 4. Zero-Knowledge Account Recovery (3-Step Wizard)

| Step | Client Actions | Server Actions |
|------|---------------|----------------|
| **1 — Verify Identity** | Derive Recovery KEK & hash from recovery key; submit hash | Lookup user by hash; return recovery-wrapped VEK + pre-generate new 2FA |
| **2 — New Password** | Decrypt VEK with Recovery KEK; re-wrap with new KEK + new salt | (No DB writes yet) |
| **3 — Force 2FA** | Scan new QR code; submit TOTP | Verify TOTP; atomic transaction: update password hash, wrapped VEK, 2FA secret; revoke all sessions; clear cookies; redirect to login with transient success message |

### 5. UI — Custom Application Modals
All confirmation and alert flows (Logout All Devices, Revoke Session, Delete Account, Regenerate Recovery Key, Reconfigure 2FA, Recovery Key Setup) use a unified custom modal system with a consistent dark design — no native browser `alert()`, `confirm()`, or `prompt()` dialogs.

---

## Key Security Architecture Diagrams

### Key Derivation Flow
```
Master Password ──► PBKDF2-HMAC-SHA256 (100k iter, vaultSalt)
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
    Auth Hash (→ server)     KEK (in-memory, non-extractable)
                                     │
                               Wraps/Unwraps
                                     ▼
                            VEK (AES-GCM 256-bit)
                                     │
                           Encrypts all vault items
```

### Vault Encryption Flow
```
[Browser]                              [Server DB]
Plaintext ──► AES-GCM(VEK) ──────────► encryptedBlob, iv, authTag
VEK       ──► AES-GCM(KEK) ──────────► encryptedVEK, vekIV, vekAuthTag
```

---

## API Hardening

- **Zod schemas** on every state-changing endpoint (registration, login, vault CRUD, recovery)
- **Base64 validation** on all cryptographic payload fields (IV, authTag, wrapped VEK)
- **UUID validation** on path parameters
- **Upstash distributed rate limiting** — 10 req/60s per IP across serverless instances; fails open if Redis is unavailable
- **Account lockout** — database-enforced 10-minute lockout after 5 failed login attempts
- **Double verification** on account deletion — requires both master password and TOTP

---

## Local Development

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
Create `apps/web/.env.local` (see `.env.example`):
```env
DATABASE_URL="mysql://root:password@127.0.0.1:3306/zk_password_manager"
JWT_SECRET="your-super-secure-random-jwt-signing-key"
UPSTASH_REDIS_REST_URL="https://your-upstash-redis-url.upstash.io"
UPSTASH_REDIS_REST_TOKEN="your_upstash_redis_token"
```

### 3. Push database schema
```bash
DATABASE_URL="mysql://root:password@127.0.0.1:3306/zk_password_manager" \
  ./packages/database/node_modules/.bin/prisma db push \
  --schema=packages/database/prisma/schema.prisma
```

### 4. Start dev server
```bash
npm run dev
# App served at http://localhost:3000
```

### 5. Production build
```bash
npm run build
```

---

## Technology Stack

| Technology | Purpose |
|-----------|---------|
| **Next.js 14** (App Router) | React UI + co-located serverless API Route Handlers |
| **TypeScript** | End-to-end type safety across all packages |
| **Web Crypto API** | Native browser AES-GCM, PBKDF2, HKDF — hardware-accelerated |
| **Argon2id** | Memory-hard server-side password hashing |
| **Prisma ORM + MySQL** | Type-safe database access; relational integrity with cascading deletes |
| **JWT + HttpOnly Cookies** | Stateless auth tokens; XSS-resistant transport |
| **Otplib + QRCode** | RFC 6238 TOTP 2FA with QR code generation |
| **Upstash Redis** | Distributed rate limiting across serverless instances |
| **Zod** | Runtime schema validation on all API payloads |
| **TurboRepo** | Monorepo orchestration, build caching, workspace dependency management |
