"use client";

import { useState } from "react";
import { api } from "../../lib/api";
import { EncryptionService, generateRecoveryKey, deriveRecoveryKEK } from "../../utils/encryption.utils";

export default function RecoverySetup({ onClose, isRotation = false }: { onClose: () => void, isRotation?: boolean }) {
    const [recoveryKey, setRecoveryKey] = useState("");
    const [loading, setLoading] = useState(false);
    const [step, setStep] = useState<"initial" | "show-key" | "confirm">("initial");
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
        // Maybe show toast?
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
            <div className={`bg-zinc-900 border ${isRotation ? "border-amber-600/30" : "border-zinc-800"} rounded-xl p-6 w-full max-w-lg shadow-2xl relative overflow-hidden`}>
                <h3 className="text-base font-bold text-white mb-2">{isRotation ? "Rotate Recovery Key" : "Recovery Key Setup"}</h3>

                {step === "initial" && (
                    <div className="space-y-4">
                        <p className="text-zinc-400 text-xs">
                            {isRotation
                                ? "Generating a new recovery key will invalidate your old one immediately."
                                : "Generate a specialized key that can restore your account if you forget your master password."}
                        </p>
                        <div className={`p-3.5 rounded-lg ${isRotation ? "bg-red-500/5 border border-red-500/10" : "bg-amber-500/5 border border-amber-500/10"}`}>
                            <p className={`${isRotation ? "text-red-400" : "text-amber-400"} text-[10px] font-bold uppercase tracking-wider mb-1`}>
                                {isRotation ? "Critical Warning" : "Warning"}
                            </p>
                            <p className={`${isRotation ? "text-red-400/80" : "text-amber-400/80"} text-xs leading-relaxed`}>
                                {isRotation
                                    ? "Any backup of your OLD recovery key will stop working. You MUST save the NEW key, or you risk permanent data loss."
                                    : "You must save this key securely. It will be shown ONLY ONCE. If you lose your password and this key, your data is lost forever."}
                            </p>
                        </div>
                        {error && <p className="text-red-400 text-xs">{error}</p>}
                        <div className="flex justify-end gap-2 mt-4">
                            <button 
                                onClick={onClose} 
                                className="px-3.5 py-1.5 rounded-lg text-zinc-400 hover:text-white transition-colors text-xs font-medium"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={generateAndSave}
                                disabled={loading}
                                className={`px-3.5 py-1.5 rounded-lg font-semibold text-xs transition-colors disabled:opacity-50 text-white ${isRotation ? "bg-amber-600 hover:bg-amber-500" : "bg-emerald-600 hover:bg-emerald-500"}`}
                            >
                                {loading ? "Generating..." : (isRotation ? "Rotate Key & Save" : "Generate Recovery Key")}
                            </button>
                        </div>
                    </div>
                )}

                {step === "show-key" && (
                    <div className="space-y-5">
                        <p className="text-zinc-400 text-xs">
                            Save this key immediately! Store it in a safe place (e.g., printed, written down, or in another secure location).
                        </p>

                        <div className="bg-zinc-950 border border-zinc-800 p-4 rounded-xl font-mono text-center break-all relative group">
                            <span className="text-emerald-400 text-base tracking-wider select-all">{recoveryKey}</span>
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

                        <div className="flex justify-end pt-2">
                            <button
                                onClick={() => {
                                    setRecoveryKey("");
                                    onClose();
                                }}
                                className="w-full py-2 bg-zinc-950 hover:bg-zinc-800 border border-zinc-850 text-white rounded-lg text-xs font-semibold transition-colors"
                            >
                                I have saved this key
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
