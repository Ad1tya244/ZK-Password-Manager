# Zero-Knowledge Password Manager

A secure, zero-knowledge password manager built as a monorepo using TurboRepo, Next.js, Express, and Prisma.

## System Architecture

This project follows a monorepo architecture managed by [TurboRepo](https://turbo.build/).

### workspace Structure
-   **`apps/web`**: The frontend application built with [Next.js 14](https://nextjs.org/) and React. It handles the user interface, client-side encryption, and communicates with the backend API.
-   **`apps/api`**: The backend REST API built with [Express](https://expressjs.com/). It handles user authentication, data persistence, and serves as the bridge to the database.
-   **`packages/crypto`**: A shared library containing cryptographic utilities, including password hashing with [Argon2](https://github.com/ranisalt/node-argon2) and encryption using [Libsodium](https://github.com/jedisct1/libsodium.js).
-   **`packages/database`**: A shared library configuring the [Prisma](https://www.prisma.io/) ORM client and database schema.
-   **`packages/shared`**: Shared types and utilities used across the application.

### Security Model
-   **Zero-Knowledge Architecture:** The master password never leaves the client device. It is used to derive a **Key Encryption Key (KEK)** locally.
-   **Vault Encryption Key (VEK):** A randomly generated key (VEK) is used to encrypt all vault items. This VEK is itself encrypted (wrapped) by the KEK and stored on the server. This allows for changing the master password without re-encrypting the entire vault.
-   **Client-Side Encryption:** All encryption and decryption happen in the browser (or client app) using robust cryptographic primitives (AES-GCM, Argon2).
-   **Authentication:** Secure authentication using JWT (JSON Web Tokens) and Argon2 password hashing. Two-Factor Authentication (2FA) is supported via TOTP (Time-based One-Time Password) using Google Authenticator or similar apps.
-   **Security Hygiene:** The `vaultSalt` is rotated upon account recovery to strictly separate the new master password's cryptographic lineage from the old one.

## Tech Stack

-   **Runtime:** Node.js
-   **Languages:** TypeScript
-   **Frontend:** Next.js 14, React 18, TailwindCSS
-   **Backend:** Express.js, cookie-parser, otplib (for 2FA)
-   **Database:** MySQL, Prisma ORM
-   **Cryptography:** Argon2, Libsodium, JWT
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
From the root directory, start the development servers for both the frontend and backend:
```bash
npm run dev
```
-   **Frontend:** `http://localhost:3000`
-   **Backend:** `http://localhost:4000`

### 6. Terminating the Project
To stop the application, press `Ctrl + C` in the terminal where the server is running.

## Features
-   User Registration & Login (Secure Auth)
-   Two-Factor Authentication (TOTP via Google Authenticator)
-   **Vault Migration:** Automatic upgrade of legacy encryption to the new VEK architecture upon login.
-   **Account Recovery:** Secure Zero-Knowledge account recovery using a generated Recovery Key.
-   Create, View, Edit, and Delete Vault Items.
-   Secure Password Generation
-   Password Strength Analysis

## Project Status
This project is currently under active development and intended for educational and research purposes. 
It is not recommended for production use without a full security audit.


