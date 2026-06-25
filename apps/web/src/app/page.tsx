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
        <main className={`flex text-white ${isAuthenticated ? "h-screen w-screen flex-col bg-[#090A0C] overflow-hidden" : "min-h-screen flex-col items-center justify-center bg-zinc-950 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-zinc-900 via-zinc-950 to-black"}`}>
            {isAuthenticated ? (
                <VaultDashboard onLogout={handleLogout} />
            ) : (
                <div className="grid grid-cols-1 lg:grid-cols-12 max-w-6xl w-full gap-10 lg:gap-16 px-6 py-12 items-center">
                    <div className="lg:col-span-7 space-y-6 text-left">
                        <div>
                            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                                Cryptographic Vault
                            </span>
                            <h1 className="text-4xl md:text-5xl font-extrabold text-white tracking-tight mt-4">
                                ZK Vault
                            </h1>
                            <p className="text-lg text-zinc-400 mt-2 font-medium">
                                Zero-Knowledge Secure Credentials Manager
                            </p>
                        </div>
                        <p className="text-zinc-400 text-sm md:text-base leading-relaxed">
                        A secure-by-default password manager where the server is treated as completely untrusted. All encryption, key derivation, and vault decryption happen locally inside your browser's Web Crypto API — the server never sees your master password or raw keys.
                        </p>
                        
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-6 border-t border-zinc-800/80">
                            {/* Feature 1 */}
                            <div className="flex gap-4 items-start">
                                <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0 bg-cyan-950/60 text-cyan-400 border border-cyan-900/40">
                                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l1.5 1.5M15.5 7.5L14 6" />
                                    </svg>
                                </div>
                                <div className="space-y-1">
                                    <h4 className="text-sm font-semibold text-zinc-200">Local PBKDF2 Stretching</h4>
                                    <p className="text-xs text-zinc-500 leading-relaxed">
                                        PBKDF2-HMAC-SHA256 (100,000 iterations) derives a KEK from your master password locally. The KEK wraps a random VEK — your password never leaves the browser.
                                    </p>
                                </div>
                            </div>

                            {/* Feature 2 */}
                            <div className="flex gap-4 items-start">
                                <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0 bg-teal-950/60 text-teal-400 border border-teal-900/40">
                                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                    </svg>
                                </div>
                                <div className="space-y-1">
                                    <h4 className="text-sm font-semibold text-zinc-200">AES-GCM 256-bit Encryption</h4>
                                    <p className="text-xs text-zinc-500 leading-relaxed">
                                        All vault items are encrypted client-side with a random 256-bit VEK using AES-GCM. Only the encrypted blob, IV, and auth tag are stored on the server.
                                    </p>
                                </div>
                            </div>

                            {/* Feature 3 */}
                            <div className="flex gap-4 items-start">
                                <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0 bg-emerald-950/60 text-emerald-400 border border-emerald-900/40">
                                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                    </svg>
                                </div>
                                <div className="space-y-1">
                                    <h4 className="text-sm font-semibold text-zinc-200">Server-Blind Recovery</h4>
                                    <p className="text-xs text-zinc-500 leading-relaxed">
                                        A 3-step ZK recovery wizard using HKDF-SHA256 lets you recover your vault with a recovery key — no server involvement, no admin overrides.
                                    </p>
                                </div>
                            </div>

                            {/* Feature 4 */}
                            <div className="flex gap-4 items-start">
                                <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0 bg-fuchsia-950/60 text-fuchsia-400 border border-fuchsia-900/40">
                                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14" />
                                    </svg>
                                </div>
                                <div className="space-y-1">
                                    <h4 className="text-sm font-semibold text-zinc-200">Argon2id Server Hashing</h4>
                                    <p className="text-xs text-zinc-500 leading-relaxed">
                                        Your authentication hash is re-hashed server-side with Argon2id — memory-hard and GPU-resistant, protecting you even if the database is breached.
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Bottom Info Bar */}
                        <div className="flex items-center gap-6 pt-6 border-t border-zinc-800/60 text-xs text-zinc-500 font-medium">
                            <div className="flex items-center gap-1.5">
                                <svg className="w-4 h-4 text-zinc-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                </svg>
                                <span>Zero-Knowledge</span>
                            </div>
                            <div className="w-px h-3 bg-zinc-800/60"></div>
                            <div className="flex items-center gap-1.5">
                                <svg className="w-4 h-4 text-zinc-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                                <span>End-to-End Encrypted</span>
                            </div>
                            <div className="w-px h-3 bg-zinc-800/60"></div>
                            <div className="flex items-center gap-1.5">
                                <svg className="w-4 h-4 text-zinc-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                                </svg>
                                <span>TOTP 2FA</span>
                            </div>
                        </div>
                    </div>
                    <div className="lg:col-span-5 flex justify-center lg:justify-end w-full">
                        <AuthForm onLogin={handleLogin} />
                    </div>
                </div>
            )}
        </main>
    );
}
