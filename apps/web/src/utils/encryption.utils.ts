import { base64ToBuffer, bufferToBase64, deriveKey, generateRandomKey, exportKey, importKey, encryptValue, decryptValue } from "@zk/crypto/client";

// Singleton to hold the secure session in memory
interface Session {
    kek: CryptoKey; // Key Encryption Key (derived from Master Password)
    vek: CryptoKey; // Vault Encryption Key (Random 256-bit key)
}

let session: Session | null = null;

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

