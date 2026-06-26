import axios from "axios";
import { EncryptionService } from "../utils/encryption.utils";

const API_URL = "/api";

export const api = axios.create({
    baseURL: API_URL,
    withCredentials: true, // Crucial for HTTP-only cookies
    headers: {
        "Content-Type": "application/json",
    },
});

api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            const requestUrl = error.config?.url || "";
            const isAuthRoute = requestUrl.includes("/auth/login") || requestUrl.includes("/auth/verify-2fa");
            
            if (!isAuthRoute) {
                // Clear local session keys so we don't think we're authenticated
                EncryptionService.clearSession();
                
                // Redirect to login page if we are in the browser
                if (typeof window !== "undefined") {
                    window.location.href = "/?error=session-expired";
                }
            }
        }
        return Promise.reject(error);
    }
);

export interface AuthResponse {
    token: string;
    user: {
        id: string;
        username: string;
        encryptedVEK?: string;
        vekIV?: string;
        vekAuthTag?: string;
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
