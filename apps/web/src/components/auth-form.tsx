"use client";

import { useState, useEffect } from "react";
import { api, AuthResponse } from "../lib/api";
import { EncryptionService, deriveRecoveryKEK } from "../utils/encryption.utils";
import { base64ToBuffer } from "@zk/crypto/client";

export default function AuthForm({ onLogin }: { onLogin: () => void }) {
    const [isLogin, setIsLogin] = useState(true);
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    const [otp, setOtp] = useState("");
    const [require2fa, setRequire2fa] = useState(false);
    const [qrCode, setQrCode] = useState("");
    const [secret, setSecret] = useState("");
    const [statusMessage, setStatusMessage] = useState("");

    // Recovery Wizard States
    const [isRecovery, setIsRecovery] = useState(false);
    const [recoveryStep, setRecoveryStep] = useState(1);
    const [recoveryUsername, setRecoveryUsername] = useState("");
    const [recoveryKey, setRecoveryKey] = useState("");
    const [newPassword, setNewPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [confirmRegisterPassword, setConfirmRegisterPassword] = useState("");

    const [recoveryData, setRecoveryData] = useState<{
        recoveredUsername: string;
        recoveryEncryptedVEK: string;
        recoveryVekIV: string;
        recoveryVekAuthTag: string;
    } | null>(null);

    const [recovery2faSecret, setRecovery2faSecret] = useState("");
    const [recovery2faQrCode, setRecovery2faQrCode] = useState("");
    const [recoveryOtp, setRecoveryOtp] = useState("");

    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const success = params.get("success");
        const errParam = params.get("error");
        if (success === "password-changed") {
            setStatusMessage("Master password changed successfully. Please sign in again.");
            window.history.replaceState({}, "", "/");
        } else if (success === "account-recovered") {
            setStatusMessage("Account recovered successfully. Please sign in again.");
            window.history.replaceState({}, "", "/");
        } else if (success === "2fa-reconfigured") {
            setStatusMessage("Two-Factor Authentication reconfigured successfully. Please sign in again.");
            window.history.replaceState({}, "", "/");
        } else if (errParam === "session-expired") {
            setError("Your session has expired. Please sign in again.");
            window.history.replaceState({}, "", "/");
        }
    }, []);

    const resetRecoveryStates = () => {
        setRecoveryStep(1);
        setRecoveryUsername("");
        setRecoveryKey("");
        setNewPassword("");
        setConfirmPassword("");
        setRecoveryData(null);
        setRecovery2faSecret("");
        setRecovery2faQrCode("");
        setRecoveryOtp("");
        setError("");
        setStatusMessage("");
    };

    const validateMasterPassword = (pwd: string) => {
        if (pwd.length < 10) return "Master Password must be at least 10 characters long";
        if (!/[A-Z]/.test(pwd)) return "Master Password must contain at least one uppercase letter";
        if (!/[!@#$%^&*(),.?":{}|<>]/.test(pwd)) return "Master Password must contain at least one special character";
        return null;
    };

    const saveVaultKey = async (vekResult: any) => {
        if (!vekResult) return;
        try {
            await api.post("/auth/vek", {
                encryptedVEK: vekResult.encryptedVEK,
                vekIV: vekResult.iv,
                vekAuthTag: vekResult.authTag
            });
            console.log("Vault key saved to server.");
        } catch (e) {
            console.error("Failed to save vault key:", e);
            setError("Failed to save vault key. Please try again.");
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError("");
        setStatusMessage("");

        try {
            if (isLogin) {
                if (require2fa) {
                    // Verify TOTP for Login
                    const res = await api.post<AuthResponse & { require2fa?: boolean, message?: string, user?: { encryptedVEK: string, vekIV: string, vekAuthTag: string, salt: string, vaultSalt?: string } }>("/auth/verify-2fa", { username, token: otp });
                    const token = res.data.token;
                    localStorage.setItem("token", token);

                    const user = res.data.user;
                    const vekData = (user?.encryptedVEK && user?.vekIV && user?.vekAuthTag)
                        ? { encryptedVEK: user.encryptedVEK, iv: user.vekIV, authTag: user.vekAuthTag }
                        : undefined;

                    const vekResult = await EncryptionService.initSession(password, user?.vaultSalt || username, vekData);

                    if (vekResult) {
                        await saveVaultKey(vekResult);
                    }

                    onLogin();
                } else {
                    // Initial Login Request
                    const res = await api.post<AuthResponse & { require2fa?: boolean, require2faSetup?: boolean, message?: string, user?: { encryptedVEK: string, vekIV: string, vekAuthTag: string, salt: string, vaultSalt?: string } }>("/auth/login", { username, password });
                    
                    if (res.data.require2faSetup) {
                        const res2fa = await api.post<{ secret: string, qrCodeUrl: string }>("/auth/enable-2fa", { username });
                        setSecret(res2fa.data.secret);
                        setQrCode(res2fa.data.qrCodeUrl);
                        setStatusMessage("Scan this QR Code with Google Authenticator to enable 2FA");
                        setRequire2fa(false);
                        setIsLogin(false);
                        setLoading(false);
                        return;
                    }

                    if (res.data.require2fa) {
                        setRequire2fa(true);
                        setStatusMessage(res.data.message || "Enter code from Google Authenticator");
                        setLoading(false);
                        return;
                    }

                    const token = res.data.token;
                    localStorage.setItem("token", token);

                    const user = res.data.user;
                    const vekData = (user?.encryptedVEK && user?.vekIV && user?.vekAuthTag)
                        ? { encryptedVEK: user.encryptedVEK, iv: user.vekIV, authTag: user.vekAuthTag }
                        : undefined;

                    const vekResult = await EncryptionService.initSession(password, user?.vaultSalt || username, vekData);

                    if (vekResult) {
                        await saveVaultKey(vekResult);
                    }

                    onLogin();
                }
            } else {
                // REGISTRATION FLOW
                if (!qrCode) {
                    // Step 1: Register
                    const validationError = validateMasterPassword(password);
                    if (validationError) {
                        setError(validationError);
                        setLoading(false);
                        return;
                    }
                    if (password !== confirmRegisterPassword) {
                        setError("Passwords do not match");
                        setLoading(false);
                        return;
                    }

                    await api.post("/auth/register", { username, password });

                    // Step 2: Get 2FA Secret & QR Code
                    const res = await api.post<{ secret: string, qrCodeUrl: string }>("/auth/enable-2fa", { username });
                    setSecret(res.data.secret);
                    setQrCode(res.data.qrCodeUrl);
                    setStatusMessage("Scan this QR Code with Google Authenticator");
                    setLoading(false);
                } else {
                    // Step 3: Verify Setup
                    const res = await api.post<AuthResponse & {
                        user?: {
                            vaultSalt: string;
                            encryptedVEK?: string;
                            vekIV?: string;
                            vekAuthTag?: string;
                        }
                    }>("/auth/verify-2fa", { username, token: otp, secret });

                    const user = res.data.user;
                    const vekData = (user?.encryptedVEK && user?.vekIV && user?.vekAuthTag)
                        ? { encryptedVEK: user.encryptedVEK, iv: user.vekIV, authTag: user.vekAuthTag }
                        : undefined;

                    const vekResult = await EncryptionService.initSession(password, user?.vaultSalt || username, vekData);

                    if (vekResult) {
                        await saveVaultKey(vekResult);
                    }

                    onLogin();
                }
            }
        } catch (err: any) {
            console.error("Login/Registration Error:", err);
            if (err.code === "ERR_NETWORK" || err.message === "Network Error") {
                setError(`Network Error: Cannot connect to server.`);
            } else {
                setError(err.response?.data?.error || err.message || "Authentication failed");
            }
        } finally {
            setLoading(false);
        }
    };

    const handleRecovery = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError("");
        setStatusMessage("");

        try {
            if (recoveryStep === 1) {
                // Step 1: Verify identity (Username & Key)
                if (!recoveryUsername) throw new Error("Username is required");
                if (!recoveryKey || recoveryKey.length !== 64) {
                    throw new Error("Recovery key must be exactly 64 characters");
                }

                // Verify recovery key hash on the server
                const { recoveryKeyHash } = await deriveRecoveryKEK(recoveryKey);
                const res = await api.post<{
                    username: string;
                    recoveryEncryptedVEK: string;
                    recoveryVekIV: string;
                    recoveryVekAuthTag: string;
                }>("/auth/recovery/init", { recoveryKeyHash });

                const { username: returnedUsername, recoveryEncryptedVEK, recoveryVekIV, recoveryVekAuthTag } = res.data;

                if (!returnedUsername || !recoveryEncryptedVEK || !recoveryVekIV || !recoveryVekAuthTag) {
                    throw new Error("No recovery data found for this key.");
                }

                // Ensure username matches
                if (returnedUsername.toLowerCase() !== recoveryUsername.toLowerCase()) {
                    throw new Error("Invalid username or recovery key combo.");
                }

                // Pre-generate the 2FA secret and QR code for step 3
                const enableRes = await api.post<{ secret: string, qrCodeUrl: string }>("/auth/enable-2fa", { username: returnedUsername });

                setRecovery2faSecret(enableRes.data.secret);
                setRecovery2faQrCode(enableRes.data.qrCodeUrl);

                setRecoveryData({
                    recoveredUsername: returnedUsername,
                    recoveryEncryptedVEK,
                    recoveryVekIV,
                    recoveryVekAuthTag
                });

                setRecoveryStep(2);
                setStatusMessage("Identity verified. Choose a new Master Password.");
            } else if (recoveryStep === 2) {
                // Step 2: Choose new master password
                const valErr = validateMasterPassword(newPassword);
                if (valErr) throw new Error(valErr);

                if (newPassword !== confirmPassword) {
                    throw new Error("Passwords do not match");
                }

                setRecoveryStep(3);
                setStatusMessage("Scan the QR code to set up mandatory 2FA.");
            } else if (recoveryStep === 3) {
                // Step 3: Enforce mandatory 2FA and submit recovery transaction
                if (!recoveryOtp || recoveryOtp.length !== 6) {
                    throw new Error("2FA code must be exactly 6 digits");
                }
                if (!recoveryData) {
                    throw new Error("Session expired. Please restart the recovery process.");
                }

                const { kek, recoveryKeyHash } = await deriveRecoveryKEK(recoveryKey);

                // Unwrap VEK using Recovery KEK
                const ciphertext = base64ToBuffer(recoveryData.recoveryEncryptedVEK);
                const iv = base64ToBuffer(recoveryData.recoveryVekIV);
                const tag = base64ToBuffer(recoveryData.recoveryVekAuthTag);

                const combined = new Uint8Array(ciphertext.byteLength + tag.byteLength);
                combined.set(new Uint8Array(ciphertext));
                combined.set(new Uint8Array(tag), ciphertext.byteLength);

                const rawVek = await window.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv as BufferSource },
                    kek,
                    combined as BufferSource
                );

                // Re-wrap VEK with the new master password
                const restoreResult = await EncryptionService.restoreSession(newPassword, rawVek);

                // Submit full recovery payload to the database
                const res = await api.post<AuthResponse & {
                    user?: {
                        id: string;
                        username: string;
                        encryptedVEK?: string;
                        vekIV?: string;
                        vekAuthTag?: string;
                        vaultSalt: string;
                        hasRecovery: boolean;
                        recoveryConfiguredAt: string;
                    }
                }>("/auth/recovery/reset", {
                    recoveryKeyHash,
                    newPassword: newPassword,
                    newEncryptedVEK: restoreResult.encryptedVEK,
                    newVekIV: restoreResult.iv,
                    newVekAuthTag: restoreResult.authTag,
                    newVaultSalt: restoreResult.newVaultSalt,
                    twoFactorSecret: recovery2faSecret,
                    totpToken: recoveryOtp
                });

                // Clear local session and storage token
                EncryptionService.clearSession();
                localStorage.removeItem("token");

                // Immediately redirect to login with query param
                window.location.href = "/?success=account-recovered";
            }
        } catch (err: any) {
            console.error("Recovery Wizard Error:", err);
            if (err.code === "ERR_NETWORK" || err.message === "Network Error") {
                setError(`Network Error: Cannot connect to server.`);
            } else {
                setError(err.response?.data?.error || err.message || "Recovery failed");
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="w-full max-w-md bg-[#0c0d0e]/60 border border-zinc-800/80 p-8 rounded-xl relative overflow-hidden shadow-2xl backdrop-blur-sm">
            <h2 className="text-2xl font-bold mb-1.5 text-white text-center tracking-tight font-sans">
                {isRecovery ? (
                    recoveryStep === 1 ? "Recovery: Step 1" : (recoveryStep === 2 ? "Recovery: Step 2" : "Recovery: Step 3")
                ) : (
                    qrCode ? "Setup 2FA" : (require2fa ? "Two-Factor Auth" : (isLogin ? "Welcome Back" : "Welcome to Vault"))
                )}
            </h2>
            <p className="text-zinc-500 text-center mb-6 text-xs font-medium">
                {isRecovery ? (
                    recoveryStep === 1 ? "Verify your username & recovery key" : (recoveryStep === 2 ? "Set your new Master Password" : "Set up mandatory 2FA")
                ) : (
                    qrCode
                        ? "Scan with Google Authenticator"
                        : (require2fa ? "Enter code from Authenticator App" : (isLogin ? "Unlock your secure vault" : "Zero-knowledge encryption setup"))
                )}
            </p>

            <form onSubmit={isRecovery ? handleRecovery : handleSubmit} className="space-y-5">
                {!require2fa && !qrCode && (
                    <div className="space-y-4">
                        {isRecovery ? (
                            <>
                                {recoveryStep === 1 && (
                                    <>
                                        <div className="space-y-1.5">
                                            <label className="text-[9px] font-bold text-zinc-500 uppercase tracking-wider ml-0.5 block">Username</label>
                                            <input
                                                type="text"
                                                value={recoveryUsername}
                                                onChange={(e) => setRecoveryUsername(e.target.value.replace(/[^a-zA-Z0-9]/g, ''))}
                                                className="w-full px-3 py-2.5 bg-zinc-950/40 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-sm placeholder-zinc-600 transition-all font-sans"
                                                placeholder="username"
                                                required
                                                autoComplete="username"
                                            />
                                        </div>
                                        <div className="space-y-1.5">
                                            <label className="text-[9px] font-bold text-zinc-500 uppercase tracking-wider ml-0.5 block">Recovery Key</label>
                                            <input
                                                type="text"
                                                value={recoveryKey}
                                                onChange={(e) => setRecoveryKey(e.target.value.replace(/[^a-fA-F0-9]/g, ''))}
                                                className="w-full px-3 py-2.5 bg-zinc-950/40 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-sm font-mono placeholder-zinc-700 transition-all"
                                                placeholder="Enter 64-character key"
                                                required
                                                autoComplete="off"
                                            />
                                        </div>
                                    </>
                                )}
                                {recoveryStep === 2 && (
                                    <>
                                        <div className="space-y-1.5">
                                            <label className="text-[9px] font-bold text-zinc-500 uppercase tracking-wider ml-0.5 block">New Master Password</label>
                                            <div className="relative flex items-center">
                                                <input
                                                    type={showPassword ? "text" : "password"}
                                                    value={newPassword}
                                                    onChange={(e) => setNewPassword(e.target.value)}
                                                    className="w-full pl-3 pr-10 py-2.5 bg-zinc-950/40 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-sm font-mono placeholder-zinc-650 transition-all"
                                                    placeholder="Create master password"
                                                    required
                                                    autoComplete="new-password"
                                                />
                                                <button
                                                    type="button"
                                                    onClick={() => setShowPassword(!showPassword)}
                                                    className="absolute right-3 text-zinc-500 hover:text-zinc-300 transition-colors"
                                                >
                                                    {showPassword ? (
                                                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                                                        </svg>
                                                    ) : (
                                                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                                        </svg>
                                                    )}
                                                </button>
                                            </div>
                                        </div>
                                        <div className="space-y-1.5">
                                            <label className="text-[9px] font-bold text-zinc-500 uppercase tracking-wider ml-0.5 block">Confirm Master Password</label>
                                            <input
                                                type={showPassword ? "text" : "password"}
                                                value={confirmPassword}
                                                onChange={(e) => setConfirmPassword(e.target.value)}
                                                className="w-full px-3 py-2.5 bg-zinc-950/40 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-sm font-mono placeholder-zinc-650 transition-all"
                                                placeholder="Confirm master password"
                                                required
                                                autoComplete="new-password"
                                            />
                                            {newPassword && confirmPassword && newPassword !== confirmPassword && (
                                                <p className="text-xs text-red-500 mt-1 ml-1 font-medium">Passwords do not match</p>
                                            )}
                                        </div>
                                    </>
                                )}
                                {recoveryStep === 3 && (
                                    <>
                                        <div className="flex flex-col items-center justify-center mb-5 bg-white p-3 rounded">
                                            <img src={recovery2faQrCode} alt="2FA QR Code" className="w-40 h-40" />
                                            <p className="text-[10px] text-zinc-500 mt-1 font-sans font-medium">Scan with Google Authenticator</p>
                                        </div>
                                        <div className="space-y-1.5">
                                            <label className="text-[9px] font-bold text-zinc-500 uppercase tracking-wider ml-0.5 block">Verification Code</label>
                                            <input
                                                type="text"
                                                value={recoveryOtp}
                                                onChange={(e) => setRecoveryOtp(e.target.value.replace(/[^0-9]/g, ''))}
                                                maxLength={6}
                                                className="w-full px-3 py-2.5 bg-zinc-950/40 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-center text-xl tracking-[0.5em] placeholder-zinc-700 transition-all font-mono"
                                                placeholder="000000"
                                                autoFocus
                                                required
                                            />
                                        </div>
                                    </>
                                )}
                            </>
                        ) : (
                            <>
                                <div className="space-y-1.5">
                                    <label className="text-[9px] font-bold text-zinc-500 uppercase tracking-wider ml-0.5 block">Username</label>
                                    <input
                                        type="text"
                                        value={username}
                                        onChange={(e) => setUsername(e.target.value.replace(/[^a-zA-Z0-9]/g, ''))}
                                        className="w-full px-3 py-2.5 bg-zinc-950/40 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-sm placeholder-zinc-600 transition-all font-sans"
                                        placeholder="username"
                                        required
                                        autoComplete="username"
                                    />
                                    {!isLogin && <p className="text-[10px] text-zinc-650 ml-0.5">Letters and numbers only.</p>}
                                </div>

                                <div className="space-y-1.5">
                                    <label className="text-[9px] font-bold text-zinc-500 uppercase tracking-wider ml-0.5 block">Master Password</label>
                                    <div className="relative flex items-center">
                                        <input
                                            type={showPassword ? "text" : "password"}
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                            className="w-full pl-3 pr-10 py-2.5 bg-zinc-950/40 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-sm font-mono placeholder-zinc-700 transition-all"
                                            placeholder="••••••••••••••••"
                                            required
                                            autoComplete={isLogin ? "current-password" : "new-password"}
                                        />
                                        <button
                                            type="button"
                                            onClick={() => setShowPassword(!showPassword)}
                                            className="absolute right-3 text-zinc-500 hover:text-zinc-300 transition-colors"
                                        >
                                            {showPassword ? (
                                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                                                </svg>
                                            ) : (
                                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                                </svg>
                                            )}
                                        </button>
                                    </div>
                                    <div className="flex items-start gap-2 mt-2 px-0.5">
                                        <svg className="w-3.5 h-3.5 text-cyan-500 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                        </svg>
                                        <p className="text-[10px] text-zinc-500 leading-tight">
                                            Your password never leaves this device. It is used to encrypt your vault locally.
                                        </p>
                                    </div>
                                </div>
                                {!isLogin && (
                                    <div className="space-y-1.5">
                                        <label className="text-[9px] font-bold text-zinc-500 uppercase tracking-wider ml-0.5 block">Confirm Master Password</label>
                                        <input
                                            type={showPassword ? "text" : "password"}
                                            value={confirmRegisterPassword}
                                            onChange={(e) => setConfirmRegisterPassword(e.target.value)}
                                            className="w-full px-3 py-2.5 bg-zinc-950/40 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-sm font-mono placeholder-zinc-650 transition-all"
                                            placeholder="Confirm master password"
                                            required
                                            autoComplete="new-password"
                                        />
                                        {password && confirmRegisterPassword && password !== confirmRegisterPassword && (
                                            <p className="text-xs text-red-500 mt-1 ml-1 font-medium">Passwords do not match</p>
                                        )}
                                    </div>
                                )}
                            </>
                        )}
                    </div>
                )}

                {qrCode && (
                    <div className="flex flex-col items-center justify-center mb-5 bg-white p-3 rounded">
                        <img src={qrCode} alt="2FA QR Code" className="w-40 h-40" />
                        <p className="text-[10px] text-gray-500 mt-1 font-medium">Scan with Authenticator App</p>
                    </div>
                )}

                {(require2fa || qrCode) && (
                    <div className="space-y-4">
                        <div className="space-y-1.5">
                            <label className="text-[9px] font-bold text-zinc-500 uppercase tracking-wider ml-0.5 block">Authenticator Code</label>
                            <input
                                type="text"
                                value={otp}
                                onChange={(e) => setOtp(e.target.value.replace(/[^0-9]/g, ''))}
                                maxLength={6}
                                className="w-full px-3 py-2.5 bg-zinc-950/40 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-center text-xl tracking-[0.5em] placeholder-zinc-700 transition-all font-mono"
                                placeholder="000000"
                                autoFocus
                                required
                            />
                        </div>
                    </div>
                )}

                {statusMessage && (
                    <div className={`p-2.5 rounded border text-xs flex items-center justify-center gap-2 ${statusMessage.toLowerCase().includes("success") ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" : "bg-cyan-500/10 border-cyan-500/20 text-cyan-400"}`}>
                        <svg className="w-3.5 h-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        {statusMessage}
                    </div>
                )}

                {error && (
                    <div className="p-2.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 text-xs flex items-center gap-2">
                        <svg className="w-3.5 h-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        {error}
                    </div>
                )}

                <button
                    type="submit"
                    disabled={loading || (!isLogin && !qrCode && password !== confirmRegisterPassword)}
                    className="w-full bg-cyan-700 hover:bg-cyan-600 text-white font-bold py-2.5 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-sm shadow-md mt-6"
                >
                    {loading ? (
                        <span className="flex items-center justify-center gap-2">
                            <svg className="animate-spin h-3.5 w-3.5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            Processing...
                        </span>
                    ) : (
                        isRecovery ? (
                            recoveryStep === 1 ? "Verify Identity" : (recoveryStep === 2 ? "Set New Password" : "Verify & Complete Recovery")
                        ) : (
                            qrCode ? "Verify Code" : (require2fa ? "Verify & Login" : (isLogin ? "Access Vault" : "Create Account"))
                        )
                    )}
                </button>
            </form>

            <div className="mt-6 text-center border-t border-zinc-800/60 pt-5 flex flex-col gap-3 text-xs">
                {!isRecovery && isLogin && !require2fa && (
                    <p className="text-zinc-500">
                        Forgot Password?{" "}
                        <button
                            type="button"
                            onClick={() => {
                                setIsRecovery(true);
                                resetRecoveryStates();
                            }}
                            className="text-emerald-405 text-emerald-400 font-semibold hover:underline bg-transparent border-none p-0 inline"
                        >
                            Recover Account
                        </button>
                    </p>
                )}

                <p className="text-zinc-500">
                    {isRecovery ? (
                        <button
                            type="button"
                            onClick={() => {
                                setIsRecovery(false);
                                resetRecoveryStates();
                                setError("");
                                setStatusMessage("");
                            }}
                            className="text-cyan-405 text-cyan-400 font-semibold hover:underline bg-transparent border-none p-0 inline"
                        >
                            Back to Login
                        </button>
                    ) : isLogin ? (
                        <>
                            New here?{" "}
                            <button
                                type="button"
                                onClick={() => {
                                    setIsLogin(false);
                                    setQrCode("");
                                    setRequire2fa(false);
                                    setOtp("");
                                    setConfirmRegisterPassword("");
                                    setError("");
                                    setStatusMessage("");
                                }}
                                className="text-cyan-405 text-cyan-400 font-semibold hover:underline bg-transparent border-none p-0 inline"
                            >
                                Create a vault
                            </button>
                        </>
                    ) : (
                        <>
                            Already have a vault?{" "}
                            <button
                                type="button"
                                onClick={() => {
                                    setIsLogin(true);
                                    setQrCode("");
                                    setRequire2fa(false);
                                    setOtp("");
                                    setConfirmRegisterPassword("");
                                    setError("");
                                    setStatusMessage("");
                                }}
                                className="text-cyan-405 text-cyan-400 font-semibold hover:underline bg-transparent border-none p-0 inline"
                            >
                                Log in
                            </button>
                        </>
                    )}
                </p>
            </div>
        </div>
    );
}
