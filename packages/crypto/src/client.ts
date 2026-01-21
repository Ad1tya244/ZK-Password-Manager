/**
 * client.ts
 * 
 * Client-side cryptographic primitives for Zero-Knowledge Architecture.
 * 
 * SECURITY GUARANTEES:
 * 1. Master Password is NEVER sent to the network.
 * 2. Key derivation happens LOCALLY in the browser using Web Crypto API.
 * 3. Encryption keys are kept in memory (CryptoKey objects) and never exported as raw bytes if possible.
 * 4. AES-GCM is used for authenticated encryption.
 */

// We use native Web Crypto API which is available in all modern browsers and Node 15+ (global.crypto)
// Ensure "lib": ["dom"] or similar is in tsconfig.

export const PBKDF2_ITERATIONS = 100000;
export const SALT_LENGTH = 16;
export const IV_LENGTH = 12; // Standard for AES-GCM

/**
 * Creates a zero-knowledge session closing over the encryption key.
 * This ensures the key object is not accessible to other parts of the application,
 * only the encrypt/decrypt capabilities are exposed.
 */
export async function createSecureSession(password: string, salt: Uint8Array) {
    const key = await deriveKey(password, salt);

    return {
        encrypt: (data: string) => encryptValue(key, data),
        decrypt: (ciphertext: ArrayBuffer, iv: Uint8Array) => decryptValue(key, ciphertext, iv),
    };
}

/**
 * Derives a cryptographic key from the master password and a salt.
 * Uses PBKDF2-HMAC-SHA256 with 100,000 iterations.
 * 
 * @param password - The master password (kept in memory).
 * @param salt - A random salt (stored/retrieved from DB).
 * @returns CryptoKey - The derived key, ready for AES-GCM.
 */
export async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt as BufferSource, // Cast to satisfy strict TS
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false, // Key is non-extractable! Crucial for security.

        ["encrypt", "decrypt"]
    );
}

/**
 * Generates a random 256-bit AES-GCM key (VEK).
 */
export async function generateRandomKey(): Promise<CryptoKey> {
    return window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true, // extractable (so we can wrap it)
        ["encrypt", "decrypt"]
    );
}

/**
 * Exports a key to raw bytes.
 */
export async function exportKey(key: CryptoKey): Promise<ArrayBuffer> {
    return window.crypto.subtle.exportKey("raw", key);
}

/**
 * Imports a key from raw bytes.
 */
export async function importKey(raw: ArrayBuffer): Promise<CryptoKey> {
    return window.crypto.subtle.importKey(
        "raw",
        raw,
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
}

/**
 * Encrypts data using the derived key.
 * 
 * @param key - The derived AES-GCM key.
 * @param data - The plaintext data.
 * @returns Object containing ciphertext and IV (Initialization Vector).
 */
export async function encryptValue(key: CryptoKey, data: string | ArrayBuffer): Promise<{ ciphertext: ArrayBuffer; iv: Uint8Array }> {
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const encodedData = typeof data === "string" ? enc.encode(data) : data;

    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv as BufferSource,
        },
        key,
        encodedData
    );

    return { ciphertext, iv };
}

/**
 * Decrypts data using the derived key.
 * 
 * @param key - The derived AES-GCM key.
 * @param ciphertext - The encrypted data.
 * @param iv - The initialization vector used for encryption.
 * @returns The decrypted plaintext string.
 */
export async function decryptValue(key: CryptoKey, ciphertext: ArrayBuffer, iv: Uint8Array): Promise<string> {
    try {
        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv as BufferSource,
            },
            key,
            ciphertext
        );

        const dec = new TextDecoder();
        return dec.decode(decrypted);
    } catch (e) {
        throw new Error("Decryption failed. Invalid password or corrupted data.");
    }
}

/**
 * Helper to convert Uint8Array/ArrayBuffer to Base64 string for storage.
 */
export function bufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = new Uint8Array(buffer as ArrayBuffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

/**
 * Helper to convert Base64 string back to Uint8Array.
 */
export function base64ToBuffer(base64: string): Uint8Array {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}
