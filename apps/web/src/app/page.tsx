"use client";

import { useEffect, useState } from "react";
import AuthForm from "../components/auth-form";
import VaultDashboard from "../components/vault-dashboard";
import { api } from "../lib/api";
import { EncryptionService } from "../utils/encryption.utils";

export default function Home() {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const checkAuth = async () => {
            try {
                // If we have a session cookie but no encryption key (e.g. page reload),
                // we must treat it as logged out because we can't decrypt anything.
                if (EncryptionService.hasSession()) {
                    await api.get("/auth/me");
                    setIsAuthenticated(true);
                } else {
                    // No key = Force re-login to derive key again
                    setIsAuthenticated(false);
                    // Optional: Call logout to clear any stale cookies
                    // await api.post("/auth/logout").catch(() => {});
                }
            } catch (e) {
                setIsAuthenticated(false);
            } finally {
                setLoading(false);
            }
        };

        checkAuth();
    }, []);

    const handleLogin = () => setIsAuthenticated(true);
    const handleLogout = async () => {
        try {
            await api.post("/auth/logout");
        } catch (e) {
            console.error("Logout API failed", e);
        } finally {
            EncryptionService.clearSession();
            setIsAuthenticated(false);
        }
    };

    if (loading) return <main className="p-24 text-center">Loading...</main>;

    return (
        <main className="flex min-h-screen flex-col items-center justify-center bg-slate-950 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900 via-slate-950 to-black text-white">
            {isAuthenticated ? (
                <VaultDashboard onLogout={handleLogout} />
            ) : (
                <div className="flex flex-col items-center w-full px-4">
                    <div className="mb-8 text-center">
                        <h1 className="text-5xl font-black mb-3 bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400 tracking-tight">
                            ZK Vault
                        </h1>
                        <p className="text-slate-500 font-medium">Zero-Knowledge Architecture</p>
                    </div>
                    <AuthForm onLogin={handleLogin} />
                </div>
            )}
        </main>
    );
}
