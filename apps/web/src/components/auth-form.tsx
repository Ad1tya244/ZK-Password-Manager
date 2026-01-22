"use client";

import { useState } from "react";
import { api, AuthResponse, VaultItem } from "../lib/api";
import { EncryptionService, deriveRecoveryKEK } from "../utils/encryption.utils";
import { bufferToBase64, base64ToBuffer } from "@zk/crypto/client";


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

    // Recovery State
    const [isRecovery, setIsRecovery] = useState(false);
    const [recoveryKey, setRecoveryKey] = useState("");
    const [newPassword, setNewPassword] = useState("");

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

                    const vekResult = await EncryptionService.initSession(password, res.data.user?.vaultSalt || username, {
                        encryptedVEK: res.data.user?.encryptedVEK,
                        iv: res.data.user?.vekIV,
                        authTag: res.data.user?.vekAuthTag
                    });

                    // If a new VEK was generated (e.g., migration or first login without VEK), save it clearly
                    if (vekResult) {
                        await saveVaultKey(vekResult);
                    }

                    onLogin();
                } else {
                    // Initial Login Request
                    const res = await api.post<AuthResponse & { require2fa?: boolean, message?: string, user?: { encryptedVEK: string, vekIV: string, vekAuthTag: string, salt: string, vaultSalt?: string } }>("/auth/login", { username, password });
                    if (res.data.require2fa) {
                        setRequire2fa(true);
                        setStatusMessage(res.data.message || "Enter code from Google Authenticator");
                        setLoading(false);
                        return;
                    }

                    const token = res.data.token;
                    localStorage.setItem("token", token);

                    // Initialize Encryption Session (Prioritize vaultSalt or Username)
                    const vekResult = await EncryptionService.initSession(password, res.data.user?.vaultSalt || username, {
                        encryptedVEK: res.data.user?.encryptedVEK,
                        iv: res.data.user?.vekIV,
                        authTag: res.data.user?.vekAuthTag
                    });

                    // If a new VEK was generated, save it
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

                    await api.post("/auth/register", { username, password });

                    // Step 2: Get 2FA Secret & QR Code
                    const res = await api.post<{ secret: string, qrCodeUrl: string }>("/auth/enable-2fa", { username });
                    setSecret(res.data.secret);
                    setQrCode(res.data.qrCodeUrl);
                    setStatusMessage("Scan this QR Code with Google Authenticator");
                    setLoading(false);
                } else {
                    // Step 3: Verify Setup
                    // Note: verify-2fa returns the USER object including vaultSalt
                    const res = await api.post<AuthResponse & { user?: { vaultSalt: string } }>("/auth/verify-2fa", { username, token: otp, secret });

                    // Use the server-provided vaultSalt for initialization
                    const vekResult = await EncryptionService.initSession(password, res.data.user?.vaultSalt || username);

                    // SAVE the new VEK immediately!
                    if (vekResult) {
                        await saveVaultKey(vekResult);
                    }

                    onLogin();
                }
            }
        } catch (err: any) {
            console.error("Login Error Details:", err);
            // Log if it's a network error explicitly
            if (err.code === "ERR_NETWORK" || err.message === "Network Error") {
                setError(`Network Error: Cannot connect to server at ${api.defaults.baseURL}. Check if server is running.`);
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

        try {
            // 1. Derive KEK and Hash from Recovery Key
            const { kek, recoveryKeyHash } = await deriveRecoveryKEK(recoveryKey);

            // 2. Fetch Encrypted Blobs from Server
            const res = await api.post<{
                recoveryEncryptedVEK: string;
                recoveryVekIV: string;
                recoveryVekAuthTag: string;
            }>("/auth/recovery/init", { recoveryKeyHash });
            const { recoveryEncryptedVEK, recoveryVekIV, recoveryVekAuthTag } = res.data;

            if (!recoveryEncryptedVEK || !recoveryVekIV || !recoveryVekAuthTag) {
                throw new Error("No recovery data found for this key.");
            }

            // 3. Unwrap VEK using Recovery KEK
            // We need a helper for this in EncryptionService? 
            // Or just manually do it here since we have the KEK and blobs.
            // But we need to use `window.crypto.subtle.decrypt`.
            // Let's use the internal logic or standard WebCrypto.
            // Since `EncryptionService` manages the session, we should use it to "Initialize Session from Recovery".
            // But `EncryptionService.initSession` takes a password.
            // We need `EncryptionService.initSessionWithRecovery(recoveryKEK, vekData)`.
            // OR simpler: decrypt VEK here, then pass it to `initSession`? 
            // EncryptionService expects `vekData` (encrypted with password-derived KEK).
            // Here we have VEK encrypted with Recovery KEK.

            // Let's decrypt the VEK bytes directly here.
            const ciphertext = base64ToBuffer(recoveryEncryptedVEK);
            const iv = base64ToBuffer(recoveryVekIV);
            const tag = base64ToBuffer(recoveryVekAuthTag);

            // Note: `base64ToBuffer` is not exposed globally, imported from `@zk/crypto/client`.
            // I imported it at top.
            // Wait, I need to check imports. `import { base64ToBuffer } ...`
            // So `base64ToBuffer` is available.

            // Construct combined buffer for decrypt logic (assuming standard GCM usage in this project)
            // But wait, `EncryptionService` helpers do combined. 
            // Let's manually decrypt using standard GCM if possible.
            // Or better: Use `EncryptionService` to init session with raw key?
            // `EncryptionService` doesn't support init with raw key.

            // Let's do manual decryption here.
            const combined = new Uint8Array(ciphertext.byteLength + tag.byteLength);
            combined.set(new Uint8Array(ciphertext));
            combined.set(new Uint8Array(tag), ciphertext.byteLength);

            const rawVek = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv as BufferSource },
                kek, // The Recovery KEK
                combined as BufferSource
            );

            // Now we have the Raw VEK.
            // We need to RE-ENCRYPT it with the NEW Password.
            // 4. Validate New Password
            const valErr = validateMasterPassword(newPassword);
            if (valErr) throw new Error(valErr);

            // 5. Initialize a NEW Session with New Password and the Existing Raw VEK
            // But `EncryptionService.initSession` generates a new random VEK if none provided.
            // OR if provided, unwraps it with password-derived KEK.
            // We have neither. We have Raw VEK.
            // We need `EncryptionService.initSessionWithRawVEK(password, rawVEK)`.
            // I should add this method? 
            // OR: I can just use `EncryptionService` to wrap the VEK with new password KEK manually?
            // Yes, calling `deriveKey(newPassword)`...

            // Let's ADD `initSessionWithRawVEK` to EncryptionService. it is cleaner.
            // I'll assume it exists for now and update EncryptionService next step?
            // No, preventing errors is better.
            // I'll stick to: 
            // a) Derive KEK for New Password. 
            // b) Wrap Raw VEK with New Password KEK.
            // c) Call `recoverAccount` API with new encrypted blobs.

            // Actually, `EncryptionService.initSession` sets the global session. We want that.
            // If I add `EncryptionService.setSession(kek, vek)`, I can use it.
            // But `initSession` does logic.

            // Let's just Add `restoreSession(password, rawVEK)` to EncryptionService.
            // I'll implement it shortly.

            // For now, in this file:
            // I will use `EncryptionService.restoreSession(newPassword, rawVek)`.
            // This method will:
            // 1. Derive KEK from newPassword (and random salt).
            // 2. Wrap `rawVek` with KEK.
            // 3. Set global session.
            // 4. Return the new stored blobs (encryptedVEK, iv, authTag, salt).

            const restoreResult = await EncryptionService.restoreSession(newPassword, rawVek);

            // 6. Submit to Server
            // 6. Submit to Server
            await api.post("/auth/recovery/reset", {
                recoveryKeyHash,
                newPassword: newPassword, // API will hash it
                newEncryptedVEK: restoreResult.encryptedVEK,
                newVekIV: restoreResult.iv,
                newVekAuthTag: restoreResult.authTag,
                newVaultSalt: restoreResult.newVaultSalt
            });

            setIsRecovery(false);
            setIsLogin(true);
            setRecoveryKey("");
            setNewPassword("");
            setPassword(""); // Clear any previous input
            setStatusMessage("Recovery successful! Please log in with your new password.");

            // onLogin(); // Do NOT auto-login, as we don't have a token/cookie yet. User must log in.
        } catch (err: any) {
            console.error("Recovery Error:", err);
            // Log if it's a network error explicitly
            if (err.code === "ERR_NETWORK" || err.message === "Network Error") {
                setError(`Network Error: Cannot connect to server at ${api.defaults.baseURL}. Check if server is running.`);
            } else {
                setError(err.response?.data?.error || err.message || "Recovery failed");
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="w-full max-w-md bg-slate-900/50 backdrop-blur-xl border border-slate-700 p-8 rounded-2xl shadow-2xl relative overflow-hidden">
            {/* Background decoration */}
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500"></div>

            <h2 className="text-3xl font-bold mb-2 text-white text-center tracking-tight">
                {qrCode ? "Setup 2FA" : (require2fa ? "Two-Factor Auth" : (isRecovery ? "Recover Account" : (isLogin ? "Welcome Back" : "Create Account")))}
            </h2>
            <p className="text-slate-400 text-center mb-8 text-sm">
                {qrCode
                    ? "Scan with Google Authenticator"
                    : (require2fa ? "Enter code from Authenticator App" : (isRecovery ? "Enter your Recovery Key" : (isLogin ? "Unlock your secure vault" : "Zero-knowledge encryption setup")))
                }
            </p>

            <form onSubmit={isRecovery ? handleRecovery : handleSubmit} className="space-y-6">
                {!require2fa && !qrCode && (
                    <div className="space-y-4">
                        {isRecovery ? (
                            // RECOVERY INPUTS
                            <>
                                <div className="space-y-2">
                                    <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider ml-1">Recovery Key</label>
                                    <input
                                        type="text"
                                        value={recoveryKey}
                                        onChange={(e) => setRecoveryKey(e.target.value.replace(/[^a-fA-F0-9]/g, ''))} // Hex only
                                        className="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-transparent outline-none text-white text-sm font-mono placeholder-slate-600 transition-all shadow-inner"
                                        placeholder="Enter your 64-character recovery key"
                                        required
                                        autoComplete="off"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider ml-1">New Master Password</label>
                                    <div className="relative">
                                        <input
                                            type={showPassword ? "text" : "password"}
                                            value={newPassword}
                                            onChange={(e) => setNewPassword(e.target.value)}
                                            className="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-transparent outline-none text-white placeholder-slate-500 transition-all font-mono shadow-inner pr-10"
                                            placeholder="Create new master password"
                                            required
                                            autoComplete="new-password"
                                        />
                                        <button
                                            type="button"
                                            onClick={() => setShowPassword(!showPassword)}
                                            className="absolute right-3 top-3.5 text-slate-500 hover:text-slate-300 transition-colors"
                                        >
                                            {showPassword ? (
                                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                                                </svg>
                                            ) : (
                                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                                </svg>
                                            )}
                                        </button>
                                    </div>
                                    <div className="flex items-start gap-2 mt-2 px-1">
                                        <svg className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                        </svg>
                                        <p className="text-[10px] text-slate-400 leading-tight">
                                            We'll re-encrypt your vault with this new password. If you lose this, you'll need your Recovery Key again.
                                        </p>
                                    </div>
                                </div>
                            </>
                        ) : (
                            // NORMAL LOGIN/REGISTER INPUTS
                            <>
                                <div className="space-y-2">
                                    <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider ml-1">Username</label>
                                    <input
                                        type="text"
                                        value={username}
                                        onChange={(e) => setUsername(e.target.value.replace(/[^a-zA-Z0-9]/g, ''))}
                                        className="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-white placeholder-slate-500 transition-all shadow-inner"
                                        placeholder="username"
                                        required
                                        autoComplete="username"
                                    />
                                    {!isLogin && <p className="text-[10px] text-slate-500 ml-1">Letters and numbers only.</p>}
                                </div>

                                <div className="space-y-2">
                                    <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider ml-1">Master Password</label>
                                    <div className="relative">
                                        <input
                                            type={showPassword ? "text" : "password"}
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                            className="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-white placeholder-slate-500 transition-all font-mono shadow-inner pr-10"
                                            placeholder="••••••••••••"
                                            required
                                            autoComplete={isLogin ? "current-password" : "new-password"}
                                        />
                                        <button
                                            type="button"
                                            onClick={() => setShowPassword(!showPassword)}
                                            className="absolute right-3 top-3.5 text-slate-500 hover:text-slate-300 transition-colors"
                                        >
                                            {showPassword ? (
                                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                                                </svg>
                                            ) : (
                                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                                </svg>
                                            )}
                                        </button>
                                    </div>
                                    <div className="flex items-start gap-2 mt-2 px-1">
                                        <svg className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                        </svg>
                                        <p className="text-[10px] text-slate-400 leading-tight">
                                            Your password never leaves this device. It is used to encrypt your vault locally.
                                        </p>
                                    </div>
                                </div>
                            </>
                        )}
                    </div>
                )}

                {qrCode && (
                    <div className="flex flex-col items-center justify-center mb-6 bg-white p-4 rounded-xl">
                        <img src={qrCode} alt="2FA QR Code" className="w-48 h-48" />
                        <p className="text-xs text-gray-500 mt-2">Scan with Authenticator App</p>
                    </div>
                )}

                {(require2fa || qrCode) && (
                    <div className="space-y-4 animate-in fade-in slide-in-from-bottom-4 duration-500">
                        <div className="space-y-2">
                            <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider ml-1">Authenticator Code</label>
                            <input
                                type="text"
                                value={otp}
                                onChange={(e) => setOtp(e.target.value.replace(/[^0-9]/g, ''))}
                                maxLength={6}
                                className="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-white text-center text-2xl tracking-[0.5em] placeholder-slate-700 transition-all shadow-inner font-mono"
                                placeholder="000000"
                                autoFocus
                                required
                            />
                        </div>
                    </div>
                )}

                {statusMessage && (
                    <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 text-sm flex items-center justify-center gap-2">
                        <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        {statusMessage}
                    </div>
                )}

                {error && (
                    <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm flex items-center gap-2">
                        <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        {error}
                    </div>
                )}

                <button
                    type="submit"
                    disabled={loading}
                    className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-semibold py-3.5 rounded-xl shadow-lg shadow-blue-500/20 transform transition-all active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
                >
                    {loading ? (
                        <span className="flex items-center justify-center gap-2">
                            <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            Processing...
                        </span>
                    ) : (qrCode ? "Verify Code" : (require2fa ? "Verify & Login" : (isRecovery ? "Recover Account" : (isLogin ? "Access Vault" : "Create Account"))))}
                </button>
            </form>

            <div className="mt-8 text-center border-t border-slate-700/50 pt-6 flex flex-col gap-3">
                {!isRecovery && isLogin && !require2fa && (
                    <button
                        onClick={() => {
                            setIsRecovery(true);
                            setError("");
                        }}
                        className="text-slate-400 text-xs hover:text-white transition-colors"
                    >
                        Forgot Password? <span className="text-emerald-400 hover:underline">Recover Account</span>
                    </button>
                )}

                <button
                    onClick={() => {
                        if (isRecovery) {
                            setIsRecovery(false);
                            setRecoveryKey("");
                            setNewPassword("");
                        } else {
                            setIsLogin(!isLogin);
                            setQrCode("");
                            setRequire2fa(false);
                            setOtp("");
                        }
                        setError("");
                        setStatusMessage("");
                    }}
                    className="text-slate-400 text-sm hover:text-white transition-colors"
                >
                    {isRecovery ? (
                        <span className="text-slate-400 hover:underline">Back to Login</span>
                    ) : (isLogin ? (
                        <>New here? <span className="text-blue-400 hover:underline">Create a vault</span></>
                    ) : (
                        <>Already have a vault? <span className="text-blue-400 hover:underline">Log in</span></>
                    ))}
                </button>
            </div>
        </div >
    );
}
