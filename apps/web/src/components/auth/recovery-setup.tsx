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
            <div className={`bg-slate-900 border ${isRotation ? "border-amber-500/30" : "border-slate-700"} rounded-2xl p-6 w-full max-w-lg shadow-2xl relative overflow-hidden`}>
                <div className={`absolute top-0 left-0 w-full h-1 ${isRotation ? "bg-gradient-to-r from-amber-500 to-orange-500" : "bg-gradient-to-r from-emerald-500 to-teal-500"}`}></div>

                <h3 className="text-xl font-bold text-white mb-2">{isRotation ? "Rotate Recovery Key" : "Recovery Key Setup"}</h3>

                {step === "initial" && (
                    <div className="space-y-4">
                        <p className="text-slate-300 text-sm">
                            {isRotation
                                ? "Generating a new recovery key will invalidate your old one immediately."
                                : "Generate a specialized key that can restore your account if you forget your master password."}
                        </p>
                        <div className={`p-4 rounded-lg ${isRotation ? "bg-red-500/10 border border-red-500/20" : "bg-yellow-500/10 border border-yellow-500/20"}`}>
                            <p className={`${isRotation ? "text-red-400" : "text-yellow-200"} text-xs font-semibold uppercase tracking-wide mb-1`}>
                                {isRotation ? "Critical Warning" : "Warning"}
                            </p>
                            <p className={`${isRotation ? "text-red-300" : "text-yellow-100/80"} text-sm leading-relaxed`}>
                                {isRotation
                                    ? "Any backup of your OLD recovery key will stop working. You MUST save the NEW key, or you risk permanent data loss."
                                    : "You must save this key securely. It will be shown ONLY ONCE. If you lose your password and this key, your data is lost forever."}
                            </p>
                        </div>
                        {error && <p className="text-red-400 text-sm">{error}</p>}
                        <div className="flex justify-end gap-3 mt-4">
                            <button onClick={onClose} className="px-4 py-2 text-slate-400 hover:text-white transition-colors text-sm">Cancel</button>
                            <button
                                onClick={generateAndSave}
                                disabled={loading}
                                className={`px-6 py-2 rounded-lg font-medium transition-colors disabled:opacity-50 text-white ${isRotation ? "bg-amber-600 hover:bg-amber-500" : "bg-emerald-600 hover:bg-emerald-500"}`}
                            >
                                {loading ? "Generating..." : (isRotation ? "Rotate Key & Save" : "Generate Recovery Key")}
                            </button>
                        </div>
                    </div>
                )}

                {step === "show-key" && (
                    <div className="space-y-5">
                        <p className="text-slate-300 text-sm">
                            Save this key immediately! Store it in a safe place (e.g., printed, written down, or in another secure location).
                        </p>

                        <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl font-mono text-center break-all relative group">
                            <span className="text-emerald-400 text-lg tracking-wider">{recoveryKey}</span>
                            <button
                                onClick={copyToClipboard}
                                className="absolute top-2 right-2 p-2 bg-slate-800 text-slate-400 rounded hover:text-white hover:bg-slate-700 transition-all opacity-0 group-hover:opacity-100"
                                title="Copy"
                            >
                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                </svg>
                            </button>
                        </div>

                        <div className="flex justify-end gap-3">
                            <button
                                onClick={() => {
                                    setRecoveryKey("");
                                    onClose();
                                }}
                                className="w-full px-6 py-3 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white rounded-lg font-medium transition-colors"
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
