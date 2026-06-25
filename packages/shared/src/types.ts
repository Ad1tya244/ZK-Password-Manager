export interface TokenPayload {
    userId: string;
    username: string;
}

export interface DecryptedVaultItem {
    id: string;
    userId: string;
    encryptedBlob: string;
    iv: string;
    authTag: string;
    site: string;
    username: string;
    password: string;
    notes?: string;
    createdAt: string;
    updatedAt: string;
}
