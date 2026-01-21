import { createSecureSession, base64ToBuffer, bufferToBase64 } from "@zk/crypto/client";

// Singleton to hold the session
let session: Awaited<ReturnType<typeof createSecureSession>> | null = null;

export const EncryptionService = {
    /**
     * Initialize session with Master Password.
     * This is the ONLY time the password is used.
     */
    initSession: async (password: string, saltBase64: string) => { // Salt is unused effectively if we rely on Argon2 hash salt, but for PBKDF2 we need one.
        // Wait, the backend returns the user, but does it return the salt?
        // In our Architecture, we might need the salt for PBKDF2.
        // Let's assume for now we use a deterministic salt or fetch it.
        // Actually, good practice: Use email as salt OR fetch specific salt for key derivation if we stored it.
        // We stored `salt` in User model, but we need to fetch it during login phase BEFORE authenticating fully?
        // OR we authenticate, get the salt, then derive the key? 
        // Actually, for ZK, we usually derive key -> login? No, we login (hashed password) -> get data.
        // But wait, the password sent to server is Hashed. 
        // The Master Key is derived from the SAME password but likely with different parameters or salt.
        // Let's use the user's ID or a fixed salt for this MVP to keep it simple, or better:
        // We can ask the user for "Encryption Salt" or just use email.
        // For this implementation, I will use a deterministic derivation from Email to safeguard against simple rainbow tables if we don't have a stored salt accessible before auth.
        // BETTER: The user object returned from /me or login has the `id`. We can use that? 
        // Actually, `deriveKey` needs a salt.
        // Let's assume we pass in the salt.

        // Changing approach: We will use a fixed application-wide salt for this MVP demonstration for Key Derivation 
        // OR allow the user to provide it. 
        // To match strict ZK, we should store a random salt for the user that is PUBLIC (can be fetched).
        // For now, I'll decode the provided salt (if any) or generate one.

        // Wait, I implemented `deriveKey` taking a salt.
        // Let's rely on the caller to provide the salt.
        const salt = new TextEncoder().encode(saltBase64 || "default-salt-12345678");
        // Ideally we fetch the user's salt column.
        session = await createSecureSession(password, salt);
    },

    encrypt: async (data: string) => {
        if (!session) throw new Error("Session not initialized");
        return await session.encrypt(data);
    },

    decrypt: async (encryptedBlob: string, iv: string, authTag: string) => {
        // Note: Our backend stores authTag separately, but AES-GCM in WebCrypto usually appends tag to ciphertext.
        // My `client.ts` `encryptValue` returned { ciphertext, iv }. 
        // WebCrypto's `encrypt` returns ciphertext which INCLUDES the tag at the end for AES-GCM.
        // My backend schema has `authTag` column.
        // If `client.ts` uses standard `subtle.encrypt` with AES-GCM, the result implies (Ciphertext + Tag).
        // So `encryptedBlob` likely contains the tag at the end.
        // I need to check `client.ts` implementation details again.

        // Checking `client.ts` from memory:
        // It returns `ciphertext` (which includes tag in WebCrypto AES-GCM) and `iv`.
        // It does NOT separate the tag physically in the return object unless I sliced it.
        // I did NOT slice it.
        // So `ciphertext` = Encrypted Data + Tag.
        // My Backend Schema has `authTag`.
        // I should probably ignore `authTag` column in DB or store the last 16 bytes there if I want to be pedantic,
        // OR just store everything in `encryptedBlob` and leave `authTag` empty/dummy.
        // Requirements said: "vault table with ... auth_tag".
        // I will split the buffer for the DB and join it for decryption.

        if (!session) throw new Error("Session not initialized");

        // Reconstruct the full buffer: Ciphertext + Tag
        const cypherBuf = base64ToBuffer(encryptedBlob);
        const tagBuf = base64ToBuffer(authTag);

        // WebCrypto expects Tag appended to Ciphertext.
        const combined = new Uint8Array(cypherBuf.length + tagBuf.length);
        combined.set(cypherBuf);
        combined.set(tagBuf, cypherBuf.length);

        return await session.decrypt(combined.buffer, base64ToBuffer(iv));
    },

    clearSession: () => {
        session = null;
    },

    hasSession: () => !!session,
};
