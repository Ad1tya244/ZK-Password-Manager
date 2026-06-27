"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
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
    const handleLogout = async (typeOrEvent?: any) => {
        const type = typeOrEvent === "delete" ? "delete" : "logout";
        if (type === "logout") {
            try {
                await api.post("/auth/logout");
            } catch (e) {
                console.error("Logout API failed", e);
            }
        }
        EncryptionService.clearSession();
        window.location.href = `/confirmation?type=${type}`;
    };

    // Sub-render: ZK Vault Branding (Badge, Title, Tagline)
    const branding = (
        <div>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse">
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Secure Digital Vault
            </span>
            <h1 className="text-4xl md:text-5xl font-extrabold text-white tracking-tight mt-4">
                ZK Vault
            </h1>
            <p className="text-lg text-zinc-400 mt-2 font-medium">
                Password security, built around your privacy.
            </p>
        </div>
    );

    // Sub-render: Description, Features Grid, and Info Badges
    const detailsAndFeatures = (isMobile: boolean = false) => (
        <>
            <p className="text-zinc-400 text-sm md:text-base leading-relaxed">
                A beautifully designed, secure-by-default vault for all your credentials. Everything is encrypted directly on your device before it ever reaches our servers, ensuring that you—and only you—can access your sensitive data. <Link href="/security" className="text-cyan-400 hover:text-cyan-300 transition-colors underline underline-offset-4 font-semibold">Learn more about our architecture.</Link>
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
                        <h4 className="text-sm font-semibold text-zinc-200">Encrypted on Your Device</h4>
                        <p className="text-xs text-zinc-500 leading-relaxed">
                            Your master password never leaves your browser. Strong security keys are generated locally on your device to lock and unlock your credentials.
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
                        <h4 className="text-sm font-semibold text-zinc-200">Zero-Knowledge Architecture</h4>
                        <p className="text-xs text-zinc-500 leading-relaxed">
                            We cannot see, access, or share your passwords. Your data is completely unreadable to anyone else, including our server administrators.
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
                        <h4 className="text-sm font-semibold text-zinc-200">Secure Recovery</h4>
                        <p className="text-xs text-zinc-500 leading-relaxed">
                            Create a personal, secure recovery key. Retain full self-custody of your vault, allowing you to safely restore access without server bypasses.
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
                        <h4 className="text-sm font-semibold text-zinc-200">Modern Security</h4>
                        <p className="text-xs text-zinc-500 leading-relaxed">
                            Robust account protection with strong server hashing and mandatory multi-factor authentication keeps your credentials safe from breach attempts.
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
        </>
    );

    if (loading) return <main className="p-24 text-center">Loading...</main>;

    return (
        <main className={`flex text-white ${isAuthenticated ? "h-screen w-screen flex-col bg-[#090A0C] overflow-hidden" : "min-h-screen flex-col items-center justify-center bg-zinc-950 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-zinc-900 via-zinc-950 to-black"}`}>
            {isAuthenticated ? (
                <VaultDashboard onLogout={handleLogout} />
            ) : (
                <>
                    {/* Mobile Layout (< md breakpoint) */}
                    <div className="md:hidden flex flex-col space-y-8 w-full px-6 py-12 max-w-md items-center">
                        <div className="w-full text-left space-y-4">
                            {branding}
                        </div>
                        <div className="w-full flex justify-center">
                            <AuthForm onLogin={handleLogin} />
                        </div>
                        <div className="w-full text-left space-y-6">
                            {detailsAndFeatures(true)}
                        </div>
                    </div>

                    {/* Tablet/Desktop Layout (>= md breakpoint) */}
                    <div className="hidden md:grid grid-cols-1 lg:grid-cols-12 max-w-6xl w-full gap-10 lg:gap-16 px-6 py-12 items-center">
                        <div className="lg:col-span-7 space-y-6 text-left">
                            {branding}
                            {detailsAndFeatures(false)}
                        </div>
                        <div className="lg:col-span-5 flex justify-center lg:justify-end w-full">
                            <AuthForm onLogin={handleLogin} />
                        </div>
                    </div>
                </>
            )}
        </main>
    );
}
