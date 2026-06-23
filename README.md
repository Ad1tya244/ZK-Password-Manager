# Zero-Knowledge Password Manager

A Zero-Knowledge, security-first password manager implementing client-side AES-GCM encryption, local PBKDF2 key derivation, Argon2id server-side password hashing, time-based OTP two-factor authentication, and Zod request verification.

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

### 3. Emergency Single-Use Recovery Key
* **Entropy**: A high-entropy 256-bit emergency recovery key is generated client-side during configuration.
* **Database Leak Protection**: The recovery key hash is derived via client-side HKDF and hashed server-side using SHA-256 before storage. Attackers with database access cannot recover the raw recovery key.
* **Single-Use Invariant**: The recovery key is consumed and invalidated immediately upon a password reset. A user can configure at most one active recovery key.
* **2FA Lockout Prevention**: Performing account recovery resets the user's 2FA configurations (`twoFactorSecret = null`). Since the holder of the recovery key already has complete cryptographic control of the vault data (via `recoveryEncryptedVEK`), requiring 2FA adds no additional cryptographic protection but presents a high risk of user lockout if both the password and the 2FA device are lost.

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

### 3. Emergency Account Recovery Flow
```
                     +-------------------------+
                     |  Plaintext Recovery Key | (256-bit emergency key)
                     +------------+------------+
                                  |
                                  v
                      +-----------+-----------+
                      |   HKDF-SHA256 Deriver |
                      +-----------+-----------+
                                  |
            +---------------------+---------------------+
            | (Key derivation KEK)                      | (One-way client hash)
            v                                           v
+-----------+-----------+                   +-----------+-----------+
|    Recovery KEK       |                   |   recoveryKeyHash     |
+-----------+-----------+                   +-----------+-----------+
            |                                           |
            | Used to unwrap                            | Sent to Server
            | recoveryEncryptedVEK                      v
            |                               +-----------+-----------+
            v                               |    SHA-256 Hasher     |
+-----------+-----------+                   +-----------+-----------+
| Decrypted VEK (Client)|                               |
+-----------+-----------+                               v
            |                               +-----------+-----------+
            v                               | Stored recoveryKeyHash|
[Encrypt VEK with new KEK]                  | (Matched in DB query) |
            |                               +-----------+-----------+
            v                                           |
      Sent to Server                                    v
+-----------+-----------+                   +-----------+-----------+
| Save new password hash|                   | Clear twoFactorSecret |
| and wrapped VEK in DB |                   | (Disable 2FA)         |
+-----------------------+                   +-----------------------+
```

---

## API Hardening & Payload Sanitization

### Zod Request Schemas
All state-changing request bodies are validated on arrival to block SQL/NoSQL injections, user enumerations, and malformed requests:
* **Registration / Login**: Enforces strict minimum lengths and regex character constraints.
* **Base64 Payload Fields**: Encryption vectors (`IV`, `authTag`, and `wrappedVEK`) are verified using Base64 regular expressions before database entry.
* **Parameters Validation**: Path parameters (like vault item UUIDs) are verified using a `z.string().uuid()` schema.

### Rate Limiting & Safety
* **Limiter Configuration**: All core auth, 2FA, and recovery routes are rate-limited per IP (10 requests per 60 seconds).
* **Memory Protection**: The rate limiter prunes expired IPs using a background interval loop. It limits maximum active entries to `10,000` to prevent memory exhaustion attacks.

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
```

### 3. Database Migration & ORM Client Generation
Initialize your database connection and compile the Prisma client engine:
```bash
cd packages/database
npx prisma db push
npx prisma generate
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
