import { base64ToBuffer, bufferToBase64, deriveKey, generateRandomKey, exportKey, importKey, encryptValue, decryptValue } from "@zk/crypto/client";

// Singleton to hold the secure session in memory
interface Session {
    kek: CryptoKey; // Key Encryption Key (derived from Master Password)
    vek: CryptoKey; // Vault Encryption Key (Random 256-bit key)
    legacyKeks?: CryptoKey[]; // Fallback KEKs for migration recovery
}

let session: Session | null = null;

export const EncryptionService = {
    /**
     * Initialize the secure session.
     * 
     * 1. Derive KEK from Master Password.
     * 2. If Encrypted VEK is provided, unwrap it using KEK.
     * 3. If no Encrypted VEK, generate a new random VEK (Migration Scenario).
     * 
     * @returns The wrapped VEK (Encrypted VEK, IV, AuthTag) if a new one was generated, otherwise null.
     */
    initSession: async (
        password: string,
        saltBase64: string,
        vekData?: { encryptedVEK: string, iv: string, authTag: string }
    ) => {
        const salt = new TextEncoder().encode(saltBase64 || "default-salt-12345678");
        const kek = await deriveKey(password, salt);

        // Generate fallback KEKs for legacy recovery
        const legacyKeks: CryptoKey[] = [];

        // 1. Try deriving with "username" as salt (common legacy pattern)
        // If saltBase64 IS the username, we already have it in 'kek'. If not, derive it.
        // We can't easily check inequality of encoded salts, so we just derive if specific conditions met.
        // Assuming 'saltBase64' passthrough from auth-form might vary.

        const saltUsername = new TextEncoder().encode(saltBase64); // If saltBase64 passed was username
        if (saltBase64) {
            const k1 = await deriveKey(password, saltUsername);
            legacyKeks.push(k1);
        }

        const saltDefault = new TextEncoder().encode("default-salt-12345678");
        const k2 = await deriveKey(password, saltDefault);
        legacyKeks.push(k2);

        let vek: CryptoKey;

        // Check if we have receive a COMPLETE VEK record from the server
        const hasStoredVEK = vekData && vekData.encryptedVEK && vekData.iv && vekData.authTag;

        if (hasStoredVEK) {
            try {
                // UNWRAP FLOW: Decrypt existing VEK using KEK
                const ciphertext = base64ToBuffer(vekData.encryptedVEK);
                const authTag = base64ToBuffer(vekData.authTag);
                const iv = base64ToBuffer(vekData.iv);

                // WebCrypto expect digest/tag appended to ciphertext for AES-GCM decryption
                const combined = new Uint8Array(ciphertext.length + authTag.length);
                combined.set(ciphertext);
                combined.set(authTag, ciphertext.length);

                // Decrypt the wrapped VEK raw bytes
                const rawVek = await window.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv as any },
                    kek,
                    combined
                );

                // Import raw bytes back into a specialized CryptoKey
                vek = await importKey(rawVek);
            } catch (error) {
                console.error("VEK Decryption/Decoding failed, falling back to new VEK:", error);
                // Fallback to MIGRATION FLOW if decryption OR decoding fails
                vek = await generateRandomKey();

                // Initialize session immediately so it's available for migration
                session = { kek, vek, legacyKeks };

                // IMPORTANT: If we fallback, we must pretend we don't have a stored VEK so we save the new one
                // The easiest way is to let the function flow down to the "if (!hasStoredVEK)" check...
                // But hasStoredVEK was true. We need to force a save.
                // We can reset hasStoredVEK-like behavior by ensuring we return the new VEK.

                // Re-implementing the RETURN logic here for the fallback case to be safe,
                // OR we could mutate a flag, but explicit return is better.

                const rawVek = await exportKey(vek);
                const { ciphertext, iv } = await encryptValue(kek, rawVek);

                const fullCiphertext = new Uint8Array(ciphertext);
                const tagLength = 16;
                const dataLength = fullCiphertext.length - tagLength;
                const encryptedVEK = fullCiphertext.slice(0, dataLength);
                const authTag = fullCiphertext.slice(dataLength);

                return {
                    encryptedVEK: bufferToBase64(encryptedVEK),
                    iv: bufferToBase64(iv),
                    authTag: bufferToBase64(authTag)
                };
            }
        } else {
            // MIGRATION FLOW: Generate new random VEK
            vek = await generateRandomKey();
        }

        session = { kek, vek, legacyKeks };

        // If we generated a new VEK (didn't use stored one), return it wrapped so the backend can store it
        if (!hasStoredVEK) {
            const rawVek = await exportKey(vek);
            const { ciphertext, iv } = await encryptValue(kek, rawVek);

            // Separate AuthTag (last 16 bytes) from Ciphertext
            const fullCiphertext = new Uint8Array(ciphertext);
            const tagLength = 16;
            const dataLength = fullCiphertext.length - tagLength;

            const encryptedVEK = fullCiphertext.slice(0, dataLength);
            const authTag = fullCiphertext.slice(dataLength);

            return {
                encryptedVEK: bufferToBase64(encryptedVEK),
                iv: bufferToBase64(iv),
                authTag: bufferToBase64(authTag)
            };
        }

        return null;
    },

    /**
     * Encrypts plaintext data using the Session VEK.
     * Returns: { ciphertext, iv, authTag } (Base64 encoded)
     */
    encrypt: async (data: string) => {
        if (!session) throw new Error("Session not initialized");

        const { ciphertext, iv } = await encryptValue(session.vek, data);

        // Separate AuthTag
        const fullCiphertext = new Uint8Array(ciphertext);
        const tagLength = 16;
        const dataLength = fullCiphertext.length - tagLength;

        const encryptedData = fullCiphertext.slice(0, dataLength);
        const authTag = fullCiphertext.slice(dataLength);

        return {
            ciphertext: encryptedData,
            iv,
            authTag
        };
    },

    /**
     * Decrypts vault data using the Session VEK.
     */
    decrypt: async (encryptedBlob: string, iv: string, authTag: string) => {
        if (!session) throw new Error("Session not initialized");

        const ciphertext = base64ToBuffer(encryptedBlob);
        const tag = base64ToBuffer(authTag);
        const ivBuffer = base64ToBuffer(iv);

        const combined = new Uint8Array(ciphertext.length + tag.length);
        combined.set(ciphertext);
        combined.set(tag, ciphertext.length);

        return await decryptValue(session.vek, combined.buffer, ivBuffer);
    },

    /**
     * Legacy Decryption: Uses KEK directly.
     * Used ONLY during migration to decrypt old items before re-encrypting with VEK.
     */
    decryptLegacy: async (encryptedBlob: string, iv: string, authTag: string) => {
        if (!session) throw new Error("Session not initialized");

        const ciphertext = base64ToBuffer(encryptedBlob);
        const tag = base64ToBuffer(authTag);
        const ivBuffer = base64ToBuffer(iv);

        const combined = new Uint8Array(ciphertext.length + tag.length);
        combined.set(ciphertext);
        combined.set(tag, ciphertext.length);

        // Try Main KEK first
        try {
            return await decryptValue(session.kek, combined.buffer, ivBuffer);
        } catch (e) {
            console.warn("Main KEK failed. Trying fallbacks...");
        }

        // Try Fallback KEKs (Legacy Recovery)
        if (session.legacyKeks && session.legacyKeks.length > 0) {
            for (const legacyKek of session.legacyKeks) {
                try {
                    console.log("Attempting legacy KEK...");
                    return await decryptValue(legacyKek, combined.buffer, ivBuffer);
                } catch (e) {
                    // Check alternative format (blob only) for this KEK
                    try {
                        return await decryptValue(legacyKek, ciphertext.buffer as ArrayBuffer, ivBuffer);
                    } catch (e2) { }
                }
            }
        }

        // Final Attempt: Alternative format on Main KEK (if not tried already inside loop)
        try {
            return await decryptValue(session.kek, ciphertext.buffer as ArrayBuffer, ivBuffer);
        } catch (e2) {
            console.error("All decryption attempts failed.");
            throw e2;
        }
    },

    clearSession: () => {
        session = null;
    },

    hasSession: () => !!session,
};
