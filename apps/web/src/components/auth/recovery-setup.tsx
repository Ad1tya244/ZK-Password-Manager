"use client";

import { useState } from "react";
import { api } from "../../lib/api";
import { EncryptionService, generateRecoveryKey, deriveRecoveryKEK } from "../../utils/encryption.utils";

export default function RecoverySetup({ onClose, isRotation = false }: { onClose: () => void, isRotation?: boolean }) {
    const [recoveryKey, setRecoveryKey] = useState("");
    const [loading, setLoading] = useState(false);
    const [step, setStep] = useState<"initial" | "show-key">("initial");
    const [error, setError] = useState("");

    const generateAndSave = async () => {
        setLoading(true);
        setError("");
        try {
            // 1. Generate Key
            const key = generateRecoveryKey();

            // 2. Derive KEK & Hash
            const { kek, recoveryKeyHash } = await deriveRecoveryKEK(key);

            // 3. Wrap VEK with Recovery KEK
            const result = await EncryptionService.wrapVEKWithKey(kek);

            // 4. Send to API
            await api.post("/auth/recovery/setup", {
                recoveryKeyHash,
                recoveryEncryptedVEK: result.encryptedVEK,
                recoveryVekIV: result.iv,
                recoveryVekAuthTag: result.authTag
            });

            setRecoveryKey(key);
            setStep("show-key");
        } catch (e: any) {
            console.error("Recovery Setup Failed:", e);
            setError(e.message || "Failed to setup recovery.");
        } finally {
            setLoading(false);
        }
    };

    const copyToClipboard = () => {
        navigator.clipboard.writeText(recoveryKey);
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/65 backdrop-blur-sm p-4">
            <div className="w-full max-w-md bg-[#111213] border border-zinc-800 rounded-lg shadow-2xl overflow-hidden">
                <div className="p-5 font-sans">
                    {/* Header */}
                    <div className="flex items-center justify-between mb-4 pb-2 border-b border-zinc-800">
                        <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                            {isRotation ? (
                                <svg className="w-4 h-4 text-amber-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                </svg>
                            ) : (
                                <svg className="w-4 h-4 text-emerald-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                                </svg>
                            )}
                            {isRotation ? "Rotate Recovery Key" : "Recovery Key Setup"}
                        </h3>
                        <button
                            onClick={onClose}
                            className="text-zinc-500 hover:text-white transition-colors"
                        >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                            </svg>
                        </button>
                    </div>

                    {step === "initial" && (
                        <div className="space-y-4">
                            <p className="text-zinc-400 text-xs leading-relaxed">
                                {isRotation
                                    ? "Generating a new recovery key will invalidate your old one immediately."
                                    : "Generate a specialized key that can restore your account if you forget your master password."}
                            </p>
                            <div className={`p-3 rounded ${isRotation ? "bg-red-500/5 border border-red-500/10" : "bg-amber-500/5 border border-amber-500/10"}`}>
                                <p className={`${isRotation ? "text-red-400" : "text-amber-300"} text-[10px] font-bold uppercase tracking-wider mb-1`}>
                                    {isRotation ? "Critical Warning" : "Warning"}
                                </p>
                                <p className="text-zinc-400 text-xs leading-relaxed">
                                    {isRotation
                                        ? "Any backup of your OLD recovery key will stop working. You MUST save the NEW key, or you risk permanent data loss."
                                        : "You must save this key securely. It will be shown ONLY ONCE. If you lose your password and this key, your data is lost forever."}
                                </p>
                            </div>
                            {error && (
                                <div className="p-2 bg-red-500/10 border border-red-500/20 text-red-400 text-[10px] rounded flex items-center gap-1.5">
                                    <svg className="w-3.5 h-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    {error}
                                </div>
                            )}
                            <div className="flex justify-end gap-2 pt-2">
                                <button
                                    onClick={onClose}
                                    className="px-3.5 py-1.5 rounded text-zinc-400 hover:text-white transition-colors text-xs font-medium border border-transparent hover:border-zinc-800 bg-[#1f2022]/40"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={generateAndSave}
                                    disabled={loading}
                                    className={`px-3.5 py-1.5 rounded font-semibold text-xs transition-colors shadow-sm disabled:opacity-50 text-emerald-100 ${isRotation ? "bg-amber-700 hover:bg-amber-600" : "bg-emerald-800 hover:bg-emerald-700"}`}
                                >
                                    {loading ? "Generating..." : (isRotation ? "Rotate Key & Save" : "Generate Recovery Key")}
                                </button>
                            </div>
                        </div>
                    )}

                    {step === "show-key" && (
                        <div className="space-y-4">
                            <p className="text-zinc-400 text-xs leading-relaxed">
                                Save this key immediately! Store it in a safe place (e.g., printed, written down, or in another secure location).
                            </p>

                            <div className="bg-zinc-950 border border-zinc-800 p-4 rounded font-mono text-center break-all relative group">
                                <span className="text-emerald-400 text-sm tracking-wider select-all">{recoveryKey}</span>
                                <button
                                    onClick={copyToClipboard}
                                    className="absolute top-2 right-2 p-1.5 bg-zinc-800 text-zinc-400 rounded hover:text-white hover:bg-zinc-700 transition-all opacity-0 group-hover:opacity-100"
                                    title="Copy Key"
                                >
                                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                    </svg>
                                </button>
                            </div>

                            <div className="p-3 bg-emerald-500/5 border border-emerald-500/10 rounded">
                                <p className="text-zinc-500 text-[10px] leading-relaxed">
                                    This key will not be shown again. Once you close this dialog, it cannot be recovered from the server.
                                </p>
                            </div>

                            <div className="flex justify-end pt-1">
                                <button
                                    onClick={() => {
                                        setRecoveryKey("");
                                        onClose();
                                    }}
                                    className="w-full py-1.5 px-3.5 rounded bg-emerald-800 hover:bg-emerald-700 text-emerald-100 font-semibold text-xs transition-colors shadow-sm"
                                >
                                    I have saved this key — Close
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
