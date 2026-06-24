# Zero-Knowledge Password Manager

A Zero-Knowledge, security-first password manager implementing client-side AES-GCM encryption, local PBKDF2 key derivation, Argon2id server-side password hashing, time-based OTP two-factor authentication, database-backed persistent sessions, and distributed rate limiting.

---

## System Architecture

This project is a monorepo managed by [TurboRepo](https://turbo.build/) containing both the client application and serverless API handlers in a single package.

### Monorepo Workspace Structure
```
├── apps/
│   └── web/                   # Next.js 14 App Router application (Frontend + co-located API Route Handlers)
├── packages/
│   ├── crypto/                # Shared package containing server-side cryptographical helpers & JWT signing
│   ├── database/              # Shared package configuring Prisma ORM and schemas
│   └── shared/                # Shared package for types and validation Zod schemas
├── package.json               # Root monorepo configuration
└── turbo.json                 # Turbo build cache configurations
```

---

## Security Model & Cryptographical Primitives

The core architectural requirement is that **the server is untrusted**. Plaintext vault items, master passwords, or raw recovery keys are never exposed over the network.

### 1. Key Derivation & Master Password Security
* **Authentication**: The client does not transmit the user's master password. Instead, it derives an **Authentication Hash** locally using PBKDF2-HMAC-SHA256 with 100,000 iterations and a unique salt.
* **Server Hashing**: Upon receipt, the server hashes the client's Authentication Hash using **Argon2id** (with a unique user salt) before comparing it against the stored value. This provides robust defense against server-side database leaks and brute-force attacks.

### 2. Vault Encryption (AES-GCM)
* **Vault Encryption Key (VEK)**: A random 256-bit AES key (VEK) is generated locally on registration. All vault entries are encrypted on the client device using **AES-GCM (256-bit)**.
* **Key Wrapping (KEK)**: The VEK is wrapped (encrypted) on the client side using the **Key Encryption Key (KEK)** derived from the master password. This allows the user to change their master password (which re-wraps the VEK) without having to re-encrypt every single item in their vault.

### 3. Persistent Session Management
* **Database-Backed Sessions**: Added a Prisma `Session` model. Access tokens are hashed using SHA-256 before being stored in the database.
* **Dual Verification**: Authed requests verify both the JWT signature and that a matching active session hash exists in the database.
* **Session Revocations**: Logout revokes the current session. Added a "Logout All Devices" endpoint that deletes all sessions for the user. Session revocation is also triggered upon password recovery and account deletion (via cascade).

### 4. Redesigned 3-Step Account Recovery Wizard
* **Wizard Sequence**:
  * **Step 1 (Verify Identity)**: Requests Username and 64-char Recovery Key. Validates recovery key hash using `/auth/recovery/init` and checks if the returned username matches user input. If correct, pre-generates the new 2FA secret and QR code via `/auth/enable-2fa`.
  * **Step 2 (Set Password)**: Prompts user to input and confirm the new master password. Validates password strength and match. Decrypts the existing VEK using the recovery KEK, and re-wraps it with the new master password KEK.
  * **Step 3 (Force 2FA)**: Displays the newly generated 2FA QR code and demands the 6-digit verification code.
* **Transactional Backend Reset**:
  * No database updates happen until the user successfully completes all steps, including mandatory 2FA configuration.
  * The `/auth/recovery/reset` endpoint verifies both the recovery key and the new 2FA code in a single transaction. On success, it overwrites the old password, vault salt, wrapped VEK, and 2FA secret in the database, revokes all previous sessions, and logs the user in immediately.
  * This prevents password-only logins after recovery and resolves user lockout risks safely.

---

## Security Architecture Diagrams

### 1. Local Key Derivation Flow
```
                     +-----------------+
                     | Master Password |
                     +--------+--------+
                              |
                              v
                  +-----------+-----------+
                  |  PBKDF2-HMAC-SHA256   | <--- Salt (from server/DB)
                  |  (100,000 iterations) |
                  +-----------+-----------+
                              |
            +-----------------+-----------------+
            |                                   | (256-bit derived key)
            v                                   v
+-----------+-----------+           +-----------+-----------+
|  Authentication Hash  |           | Key Encryption Key    |
|  (Client-side Hash)   |           | (KEK, in-memory only) |
+-----------+-----------+           +-----------+-----------+
            |                                   |
            | Sent to Server                    | Used to wrap/unwrap
            v                                   | Vault Encryption Key (VEK)
+-----------+-----------+                       |
|   Server-side Hash    |                       v
|  (Argon2id Hashing)   |           +-----------+-----------+
+-----------------------+           | Wrapped VEK           |
                                    | (Stored on Server)    |
                                    +-----------------------+
```

### 2. Vault Data Encryption/Decryption Flow
```
[Client Device (In-Memory Only)]              [Server (Database Storage)]
+------------------------------+              +--------------------------+
|  Plaintext Password (Data)   |              |                          |
|              |               |              |                          |
|              v (AES-GCM-256) |              |                          |
|  +-----------+-----------+   |  Network     |                          |
|  |     Encrypted Blob    +----------------->| Stored in Vault Table    |
|  +-----------------------+   |  Transfer    |                          |
|                              |              |                          |
|  +-----------------------+   |              |                          |
|  |  Vault Encryption Key |   |              |                          |
|  |       (VEK)           |   |              |                          |
|  +-----------+-----------+   |              |                          |
|              |               |              |                          |
|              v (AES-GCM Key  |              |                          |
|                 Wrapping)    |              |                          |
|  +-----------+-----------+   |  Network     |                          |
|  |      Wrapped VEK      +----------------->| Stored in Users Table    |
|  +-----------------------+   |  Transfer    | (recoveryEncryptedVEK /  |
|                              |              |  encryptedVEK)           |
+------------------------------+              +--------------------------+
```

### 3. Redesigned 3-Step Account Recovery Flow
```
Step 1: Identity Verification
[Input Username & Key] ---> [Derive Recovery Key Hash] ---> POST /auth/recovery/init
                                                                   |
                                                         (Verify Key & Username)
                                                                   v
                                                         Generate & return new 2FA
                                                         secret & QR code

Step 2: Password Reset
[Input New Password]   ---> [Decrypt VEK using Recovery KEK] ---> [Re-wrap VEK with new Master Password KEK]

Step 3: Mandate 2FA Setup
[Scan QR Code & Input TOTP] ---> POST /auth/recovery/reset
                                       |
                             (Verify Recovery Key & TOTP)
                                       |
                                       v
                             [Prisma Update Transaction]
                             - Update password hash, salt, wrapped VEK
                             - Save new 2FA secret (deletes old 2FA)
                             - Revoke all user DB sessions
                                       |
                                       v
                             Generate new session & JWTs
                             Set cookies -> Redirect to Vault
```

---

## API Hardening & Payload Sanitization

### Zod Request Schemas
All state-changing request bodies are validated on arrival to block SQL/NoSQL injections, user enumerations, and malformed requests:
* **Registration / Login**: Enforces strict minimum lengths, regex character constraints, and password confirmation validation.
* **Base64 Payload Fields**: Encryption vectors (`IV`, `authTag`, and `wrappedVEK`) are verified using Base64 regular expressions before database entry.
* **Parameters Validation**: Path parameters (like vault item UUIDs) are verified using a `z.string().uuid()` schema.

### Rate Limiting & Safety
* **Upstash Distributed Rate Limiting**: Replaced in-memory Map rate limiting with `@upstash/redis` and `@upstash/ratelimit` SDKs. This ensures rate limits (10 requests per 60 seconds per IP) are tracked consistently across multiple serverless instances and survive restarts.
* **Fail-Open Fallback**: Limiter fails open gracefully if the remote Redis calls time out or if credentials are unconfigured, logging warnings to ensure service availability.

---

## Local Setup & Development

### 1. Installation
Install all dependencies across workspaces from the monorepo root:
```bash
npm install
```

### 2. Environment Configurations
Create a `.env.local` file inside `apps/web` (use the root `.env.example` as a template):
```env
# apps/web/.env.local
DATABASE_URL="mysql://root:password@127.0.0.1:3306/zk_password_manager"
JWT_SECRET="your-super-secure-random-jwt-signing-key"
UPSTASH_REDIS_REST_URL="https://your-upstash-redis-url.upstash.io"
UPSTASH_REDIS_REST_TOKEN="your_upstash_redis_token"
```

### 3. Database Migration & ORM Client Generation
Initialize your database connection and compile the Prisma client engine:
```bash
DATABASE_URL="mysql://root:password@127.0.0.1:3306/zk_password_manager" ./packages/database/node_modules/.bin/prisma db push --schema=packages/database/prisma/schema.prisma
```

### 4. Running the Project
Start the Next.js development server:
```bash
npm run dev
```
The application will serve locally at **`http://localhost:3000`**.

### 5. Production Build
To run a type-checking check and compile optimized bundles for deployment:
```bash
npm run build
```
