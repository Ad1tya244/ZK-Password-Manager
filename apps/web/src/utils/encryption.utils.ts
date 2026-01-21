import { createSecureSession, base64ToBuffer, bufferToBase64, deriveKey, generateRandomKey, exportKey, importKey, encryptValue, decryptValue } from "@zk/crypto/client";

// Singleton to hold the session
interface Session {
    kek: CryptoKey; // Key Encryption Key (derived from password)
    vek: CryptoKey; // Vault Encryption Key (random, wrapped by KEK)
}

let session: Session | null = null;

export const EncryptionService = {
    /**
     * Initialize session with Master Password and VEK data.
     * If VEK data is missing, we must generate it (Migrate).
     */
    initSession: async (
        password: string,
        saltBase64: string,
        vekData?: { encryptedVEK: string, iv: string, authTag: string }
    ) => {
        const salt = new TextEncoder().encode(saltBase64 || "default-salt-12345678");
        const kek = await deriveKey(password, salt);
        let vek: CryptoKey;

        // If we have a stored VEK, decrypt it
        if (vekData && vekData.encryptedVEK) {
            const cypherBuf = base64ToBuffer(vekData.encryptedVEK);
            const tagBuf = base64ToBuffer(vekData.authTag);
            const combined = new Uint8Array(cypherBuf.length + tagBuf.length);
            combined.set(cypherBuf);
            combined.set(tagBuf, cypherBuf.length);

            // Decrypt the wrapping to get raw VEK bytes
            const dummyIv = base64ToBuffer(vekData.iv); // Actually decryptValue takes BufferSource

            // KEK decrypts the wrapped VEK
            // We reuse decryptValue but it assumes string return. 
            // We need to implement raw decryption in client.ts or just handle it here?
            // client.ts decryptValue returns string. We encrypted ArrayBuffer.
            // We need to handle this.
            // Wait, `encryptValue` in client.ts now accepts ArrayBuffer, but `decryptValue` returns string?
            // I should have checked decryptValue.
            // If I updated encryptValue, I should assume I might need to update decryptValue OR just use raw webcrypto here for unwrapping.
            // It's cleaner to use raw webcrypto for the specific task of unwrapping if the helper is strictly string-based.

            const rawVek = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: base64ToBuffer(vekData.iv) as BufferSource },
                kek,
                combined
            );

            vek = await importKey(rawVek);
        } else {
            // New VEK Generation (Migration)
            vek = await generateRandomKey();
        }

        session = { kek, vek };

        // Return the wrapped VEK so caller can save it
        if (!vekData || !vekData.encryptedVEK) {
            const rawVek = await exportKey(vek);
            const { ciphertext, iv } = await encryptValue(kek, rawVek);

            // Split tag (last 16 bytes)
            const full = new Uint8Array(ciphertext);
            const tagLen = 16;
            const dataLen = full.length - tagLen;
            const encryptedVEK = full.slice(0, dataLen);
            const authTag = full.slice(dataLen);

            return {
                encryptedVEK: bufferToBase64(encryptedVEK),
                iv: bufferToBase64(iv),
                authTag: bufferToBase64(authTag)
            };
        }
        return null;
    },

    /**
     * Encrypts data using the VEK (Vault Key).
     */
    encrypt: async (data: string) => {
        if (!session) throw new Error("Session not initialized");
        // Encrypt using VEK, not KEK
        return await encryptValue(session.vek, data);
    },

    /**
     * Decrypts buffer using the VEK.
     */
    decrypt: async (encryptedBlob: string, iv: string, authTag: string) => {
        if (!session) throw new Error("Session not initialized");

        const cypherBuf = base64ToBuffer(encryptedBlob);
        const tagBuf = base64ToBuffer(authTag);

        const combined = new Uint8Array(cypherBuf.length + tagBuf.length);
        combined.set(cypherBuf);
        combined.set(tagBuf, cypherBuf.length);

        return await decryptValue(session.vek, combined.buffer, base64ToBuffer(iv));
    },

    /**
     * Decrypts buffer using the KEK (Legacy Migration).
     */
    decryptLegacy: async (encryptedBlob: string, iv: string, authTag: string) => {
        if (!session) throw new Error("Session not initialized");

        const cypherBuf = base64ToBuffer(encryptedBlob);
        const tagBuf = base64ToBuffer(authTag);

        const combined = new Uint8Array(cypherBuf.length + tagBuf.length);
        combined.set(cypherBuf);
        combined.set(tagBuf, cypherBuf.length);

        return await decryptValue(session.kek, combined.buffer, base64ToBuffer(iv));
    },

    // Helper to get access to KEK for legacy migration if needed
    getLegacyKEK: () => {
        if (!session) throw new Error("Session not initialized");
        return session.kek;
    },

    clearSession: () => {
        session = null;
    },

    hasSession: () => !!session,
};
