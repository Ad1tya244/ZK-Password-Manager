import { base64ToBuffer, bufferToBase64, deriveKey, generateRandomKey, exportKey, importKey, encryptValue, decryptValue } from "@zk/crypto/client";

// Singleton to hold the secure session in memory
interface Session {
    kek: CryptoKey; // Key Encryption Key (derived from Master Password)
    vek: CryptoKey; // Vault Encryption Key (Random 256-bit key)
}

let session: Session | null = null;

// ------------------------------------
// Recovery Helpers
// ------------------------------------

export const generateRecoveryKey = (): string => {
    // Generate 32 bytes (256 bits) random key
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    // Return as hex string for user readability (could be mnemonics, but hex is simple)
    // Actually, hex is hard to read. Base64url is better? Or just Base64?
    // Let's use Hex for standard "Key" look, or split into groups.
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
};

export const deriveRecoveryKEK = async (recoveryKeyHex: string) => {
    // Simply import the key material
    // We treating the recovery key as high-entropy, so we can use it directly or HKDF it.
    // HKDF is safer.
    const keyBytes = new Uint8Array(recoveryKeyHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HKDF" },
        false,
        ["deriveKey", "deriveBits"]
    );

    // Derive KEK using a static info (or we could use a salt, but simple recovery is static context)
    // Actually, we want a hash for the server to verify.
    // Let's derive TWO things:
    // 1. Recovery Key Hash (for server auth)
    // 2. Recovery KEK (for wrapping VEK)

    // We need a salt. But recovery key is static.
    // We can use a static salt like "ZK_RECOVERY_SALT".
    const enc = new TextEncoder();
    const salt = enc.encode("ZK_PASSWORD_MANAGER_RECOVERY_SALT");

    const kek = await window.crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: salt,
            info: enc.encode("RECOVERY_KEK"),
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );

    // Derive Hash for Server (using SHA-256 on the key itself? No, use the HKDF output or similar)
    // Actually, let's just hash the key bytes directly for the server identifier.
    // Or usage HKDF to derive an "Identity Key".
    const identityKey = await window.crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: salt,
            info: enc.encode("RECOVERY_IDENTITY"),
        },
        keyMaterial,
        256
    );
    const recoveryKeyHash = bufferToBase64(identityKey);

    return { kek, recoveryKeyHash };
};

export const EncryptionService = {
    /**
     * Initialize the secure session.
     */
    initSession: async (
        password: string,
        vaultSalt: string | null | undefined,
        vekData?: { encryptedVEK: string, iv: string, authTag: string }
    ) => {
        // Validation/Logging
        if (vekData) {
            if (typeof vekData.encryptedVEK !== 'string' || typeof vekData.iv !== 'string' || typeof vekData.authTag !== 'string') {
                console.error("Invalid VEK Data types:", vekData);
                throw new Error("Invalid VEK format from server");
            }
        }

        // 1. Derive KEK (Key Encryption Key)
        let primarySalt = new Uint8Array(0);
        if (vaultSalt) {
            // Hex string expected from backend (32 chars for 16 bytes)
            if (vaultSalt.length === 32 && /^[0-9a-fA-F]+$/.test(vaultSalt)) {
                const match = vaultSalt.match(/.{1,2}/g);
                if (match) primarySalt = new Uint8Array(match.map(byte => parseInt(byte, 16)));
            } else {
                primarySalt = new TextEncoder().encode(vaultSalt);
            }
        }
        const kek = await deriveKey(password, primarySalt);

        let vek: CryptoKey;
        let wrappedVEK: { encryptedVEK: string, iv: string, authTag: string } | null = null;

        const hasStoredVEK = vekData && vekData.encryptedVEK && vekData.iv && vekData.authTag;

        if (hasStoredVEK) {
            // 2. Unwrap Existing VEK
            vek = await unwrapVEK(kek, vekData);
        } else {
            // 3. Generate New VEK (Migration/New User)
            vek = await generateRandomKey();
            // Wrap it immediately for storage
            wrappedVEK = await wrapVEK(kek, vek);
        }

        session = { kek, vek };

        // Return wrapped VEK only if we generated a new one
        return wrappedVEK;
    },

    encrypt: async (data: string) => {
        if (!session) throw new Error("Session not initialized");
        // ... (existing implementation is fine, calling internal helper)
        return splitEncryptedData(await encryptValue(session.vek, data));
    },

    decrypt: async (encryptedBlob: string, iv: string, authTag: string) => {
        if (!session) throw new Error("Session not initialized");
        return decryptData(session.vek, encryptedBlob, iv, authTag);
    },

    wrapVEKWithKey: async (wrappingKey: CryptoKey) => {
        if (!session) throw new Error("Session not initialized");

        const vekBytes = await window.crypto.subtle.exportKey("raw", session.vek);

        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedVEK = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            wrappingKey,
            vekBytes
        );

        return splitEncryptedData({ ciphertext: encryptedVEK, iv });
    },



    /**
     * Restore session from a raw VEK and new password (used in recovery).
     * This sets the session with the new password-derived KEK and the recovered VEK.
     * It returns the new wrapped VEK (encrypted with new password KEK) for storage.
     */
    restoreSession: async (password: string, rawVek: ArrayBuffer) => {
        // 1. Generate NEW Vault Salt
        const saltArray = window.crypto.getRandomValues(new Uint8Array(16));
        const newVaultSalt = Array.from(saltArray).map(b => b.toString(16).padStart(2, '0')).join('');

        // 2. Derive NEW KEK from new password and new salt
        const newKek = await deriveKey(password, saltArray);

        // 3. Import the Recovered VEK (if not already a Key)
        // If rawVek is ArrayBuffer, import it.
        const vek = await importKey(rawVek);

        // 4. Wrap VEK with NEW KEK
        const wrapper = await wrapVEK(newKek, vek);

        // 5. Update Session
        session = { kek: newKek, vek };

        return {
            ...wrapper,
            newVaultSalt // Return this so the caller can send it to the server
        };
    },

    clearSession: () => { session = null; },
    hasSession: () => !!session,
};

// --- Internal Helper Functions ---

async function unwrapVEK(kek: CryptoKey, vekData: { encryptedVEK: string, iv: string, authTag: string }): Promise<CryptoKey> {
    try {
        const ciphertext = base64ToBuffer(vekData.encryptedVEK);
        const authTag = base64ToBuffer(vekData.authTag);
        const iv = base64ToBuffer(vekData.iv);

        const combined = new Uint8Array(ciphertext.length + authTag.length);
        combined.set(ciphertext);
        combined.set(authTag, ciphertext.length);

        const rawVek = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv as any },
            kek,
            combined
        );
        return await importKey(rawVek);
    } catch (e) {
        console.error("VEK Unwrap Failed:", e);
        throw new Error("Failed to decrypt Vault Key.");
    }
}

async function wrapVEK(kek: CryptoKey, vek: CryptoKey) {
    const rawVek = await exportKey(vek);
    const { ciphertext, iv } = await encryptValue(kek, rawVek);
    return splitEncryptedData({ ciphertext, iv });
}

async function decryptData(key: CryptoKey, encryptedBlob: string, iv: string, authTag: string) {
    const ciphertext = base64ToBuffer(encryptedBlob);
    const tag = base64ToBuffer(authTag);
    const ivBuffer = base64ToBuffer(iv);

    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext);
    combined.set(tag, ciphertext.length);

    return await decryptValue(key, combined.buffer, ivBuffer);
}

function splitEncryptedData(result: { ciphertext: ArrayBuffer, iv: Uint8Array }) {
    const fullCiphertext = new Uint8Array(result.ciphertext);
    const tagLength = 16;
    const dataLength = fullCiphertext.length - tagLength;

    const encryptedData = fullCiphertext.slice(0, dataLength);
    const authTag = fullCiphertext.slice(dataLength);

    return {
        encryptedVEK: bufferToBase64(encryptedData), // For VEK wrapping return format
        ciphertext: bufferToBase64(encryptedData), // For generic encrypt return format (aliasing for clarity if needed, or just standardizing)
        // Wait, encrypt() returns { ciphertext, iv, authTag }. initSession returns { encryptedVEK... }.
        // Let's standardize return object or map it.
        // For wrapVEK: returning { encryptedVEK, ... }
        // For encrypt: returning { ciphertext, ... }
        // I will return a generic object and map it.
        iv: bufferToBase64(result.iv),
        authTag: bufferToBase64(authTag)
    };
}
// Fix splitEncryptedData to accommodate both output shapes or generic
function formatEncryptedOutput(result: { ciphertext: ArrayBuffer, iv: Uint8Array }) {
    const fullCiphertext = new Uint8Array(result.ciphertext);
    const tagLength = 16;
    const dataLength = fullCiphertext.length - tagLength;

    const body = fullCiphertext.slice(0, dataLength);
    const tag = fullCiphertext.slice(dataLength);

    return {
        body: bufferToBase64(body),
        iv: bufferToBase64(result.iv),
        authTag: bufferToBase64(tag)
    };
}

