import axios from "axios";

const API_URL = "/api";

export const api = axios.create({
    baseURL: API_URL,
    withCredentials: true, // Crucial for HTTP-only cookies
    headers: {
        "Content-Type": "application/json",
    },
});

export interface AuthResponse {
    user: {
        id: string;
        username: string;
    };
    require2fa?: boolean;
    message?: string;
}

export interface VaultItem {
    id: string;
    encryptedBlob: string;
    iv: string;
    authTag: string;
    createdAt: string;
}
