# Zero-Knowledge Password Manager

A Zero-Knowledge, security-first password manager implementing client-side AES-GCM encryption, Argon2 password hashing, and TOTP-based two-factor authentication in a zero-knowledge architecture.

## System Architecture

This project follows a monorepo architecture managed by [TurboRepo](https://turbo.build/).

### workspace Structure
-   **`apps/web`**: The frontend application built with [Next.js 14](https://nextjs.org/) and React. It handles the user interface, client-side encryption, and communicates with the backend API.
-   **`apps/api`**: The backend REST API built with [Express](https://expressjs.com/). It handles user authentication, data persistence, and serves as the bridge to the database.
-   **`packages/crypto`**: A shared library containing cryptographic utilities, including password hashing with [Argon2](https://github.com/ranisalt/node-argon2) and encryption using [Libsodium](https://github.com/jedisct1/libsodium.js).
-   **`packages/database`**: A shared library configuring the [Prisma](https://www.prisma.io/) ORM client and database schema.
-   **`packages/shared`**: Shared types and utilities used across the application.

### Security Model
-   **Zero-Knowledge Architecture:** The master password never leaves the client device. It is hashed (Argon2) locally for authentication and used to derive a **Key Encryption Key (KEK)** for decryption.
-   **Vault Encryption:** All vault items are encrypted using **AES-GCM (256-bit)** with a random **Vault Encryption Key (VEK)**.
-   **Key Wrapping:** The VEK is encrypted (wrapped) by the User's KEK. This allows for changing the master password (re-wrapping the VEK) without re-encrypting the entire vault.
-   **Account Recovery:** A separate, randomly generated **256-bit Recovery Key** can independently derive a KEK to unwrap the VEK, ensuring access is possible even if the master password is lost, without compromising Zero-Knowledge principles.
-   **Authentication:** Stateless JWT authentication. Critical actions (Account Deletion) require strict **Double Verification** (Master Password + TOTP).
-   **Network Security:** All sensitive endpoints are protected by **Rate Limiting** to prevent brute-force attacks.

## Tech Stack

-   **Runtime:** Node.js
-   **Languages:** TypeScript
-   **Frontend:** Next.js 14, React 18, TailwindCSS, Axios
-   **Backend:** Express.js, express-rate-limit, cookie-parser, otplib (2FA), qrcode
-   **Database:** MySQL, Prisma ORM
-   **Cryptography:** Argon2 (hashing), Libsodium (encryption), JWT
-   **Build Tool:** TurboRepo

## Dependencies

Key dependencies installed across the workspace:

### Root
-   `turbo`: Build system
-   `typescript`: Static type checker
-   `prettier`: Code formatter

### Web
-   `next`: React framework
-   `react` / `react-dom`: UI library
-   `axios`: HTTP client
-   `tailwindcss`: Utility-first CSS framework

### API
-   `express`: Web server framework
-   `prisma` / `@prisma/client`: Database ORM
-   `argon2`: Password hashing
-   `jsonwebtoken`: Auth tokens
-   `otplib`: TOTP generation/verification for 2FA
-   `qrcode`: QR code generation for 2FA setup

## System Requirements

### Software
-   **Node.js**: Version 18.17.0 or higher.
-   **npm**: Version 10.0.0 or higher (or compatible package manager).
-   **MySQL**: A running MySQL database instance (local or remote).

### Hardware
-   **RAM**: Minimum 4GB (8GB recommended for running the full dev stack smoothly).
-   **Storage**: 500MB free space for dependencies and build artifacts.

## Threat Model
- Server is assumed to be untrusted and cannot decrypt user vault data.
- Attacker may gain database access but cannot recover plaintext passwords.
- Client device compromise is considered out of scope.

## High-Level Flow
1. User enters master password.
2. Encryption keys are derived locally.
3. Vault data is encrypted on the client.
4. Encrypted data is stored on the server.
5. Server never sees plaintext or master password.

## Getting Started
### 1. Prerequisites
Ensure you have Node.js and MySQL installed and running.

### 2. Installation
Clone the repository (if applicable) and install dependencies from the root directory:
```bash
npm install
```

### 3. Environment Setup
You need to configure environment variables for the database and API.

**Database (`packages/database/.env`):**
Create or edit `.env` in `packages/database`:
```env
DATABASE_URL="mysql://USER:PASSWORD@HOST:3306/DATABASE_NAME"
```

**API (`apps/api/.env`):**
Create or edit `.env` in `apps/api`:
```env
PORT=4000
DATABASE_URL="mysql://USER:PASSWORD@HOST:3306/DATABASE_NAME"
# Add other API secrets as needed
```

### 4. Database Migration
Push the database schema to your MySQL instance:
```bash
cd packages/database
npx prisma db push
npx prisma generate
```

### 5. Running the Project
From terminal, start mysql server by running:
```bash
brew services start mysql
```
From the root directory, start the development servers for both the frontend and backend:
```bash
npm run dev
```
-   **Frontend:** `http://localhost:3000`
-   **Backend:** `http://localhost:4000`

### 6. Terminating the Project
To stop the application, press `Ctrl + C` in the terminal where the server is running.

## Features

### 🔐 Zero-Knowledge Security
-   **Client-Side Encryption:** All data is encrypted locally using AES-GCM (256-bit) before ever reaching the network.
-   **Secure Key Derivation:** Master password never leaves the device. Keys are derived using Argon2/PBKDF2.
-   **Vault Encryption Key (VEK):** Architecture supports changing the master password without re-encrypting the entire vault.

### 🛡️ Authentication & Recovery
-   **Secure Authentication:** JWT-based stateless authentication with Argon2 password hashing.
-   **Two-Factor Authentication (2FA):** Time-based One-Time Password (TOTP) integration (Google Authenticator, Authy).
-   **Account Recovery:** Zero-Knowledge recovery system using a 256-bit Recovery Key.
    -   **Recovery Key Rotation:** Ability to generate a new recovery key if the previous one is compromised.
-   **Secure Account Deletion:** Requires strictly verified Master Password AND 2FA code (if enabled) to prevent accidental loss.

### 💎 Vault Management
-   **CRUD Operations:** Create, Read, Update, and Delete encrypted passwords.
-   **Secure Item Deletion:** Critical actions require Master Password verification.
-   **Password Utilities:**
    -   Built-in strong password generator.
    -   Password strength analysis.
    -   One-click copy to clipboard with visual feedback.

### 🚀 Modern Experience & Hardening
-   **Modern UI:** Sleek, dark-mode interface using Zinc, Cyan (`#05cbf7`), Emerald (`#45d921`), and Red (`#f51d1d`).
-   **Responsive Design:** Optimized for desktop and mobile viewports.
-   **API Hardening:**
    -   Rate Limiting on sensitive endpoints (Login, Registration).
    -   Strict input validation and sanitization.

## Project Status
This project is currently under active development and intended for educational and research purposes. 
It is not recommended for production use without a full security audit.


