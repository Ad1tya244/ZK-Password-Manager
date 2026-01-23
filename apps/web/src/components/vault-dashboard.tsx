"use client";

import { useEffect, useState } from "react";
import { api, VaultItem } from "../lib/api";
import { EncryptionService } from "../utils/encryption.utils";
import { analyzePasswordStrength, StrengthResult } from "../utils/password-strength";
import RecoverySetup from "./auth/recovery-setup";

export default function VaultDashboard({ onLogout }: { onLogout: () => void }) {
    const [items, setItems] = useState<any[]>([]);
    const [hasRecovery, setHasRecovery] = useState(false);
    const [site, setSite] = useState("");
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [loading, setLoading] = useState(true);
    const [deletePassword, setDeletePassword] = useState("");
    const [isDeleting, setIsDeleting] = useState(false);
    const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
    const [deleteStep, setDeleteStep] = useState(1);
    const [copiedId, setCopiedId] = useState<string | null>(null);
    const [is2faEnabled, setIs2faEnabled] = useState(false);
    const [deleteTotp, setDeleteTotp] = useState("");

    const [showPasswordAdd, setShowPasswordAdd] = useState(false);
    const [showPasswordDelete, setShowPasswordDelete] = useState(false);

    // Recovery State
    const [isRecoveryModalOpen, setIsRecoveryModalOpen] = useState(false);

    // Edit State
    const [editingItem, setEditingItem] = useState<any>(null);
    const [editSite, setEditSite] = useState("");
    const [editUsername, setEditUsername] = useState("");
    const [editPassword, setEditPassword] = useState("");
    const [showEditPassword, setShowEditPassword] = useState(false);

    // Strength State
    const [strength, setStrength] = useState<StrengthResult>({
        score: 0,
        label: "",
        color: "bg-slate-700",
        feedback: []
    });

    const loadItems = async () => {
        try {
            const res = await api.get<VaultItem[]>("/vault");
            const decryptedItems = await Promise.all(
                res.data.map(async (item) => {
                    try {
                        const plaintext = await EncryptionService.decrypt(
                            item.encryptedBlob,
                            item.iv,
                            item.authTag
                        );
                        try {
                            return { ...item, ...JSON.parse(plaintext) };
                        } catch {
                            return { ...item, site: "Legacy Item", username: "Unknown", password: plaintext };
                        }
                    } catch (e) {
                        console.error("Decryption Failed:", item.id);
                        return { ...item, site: "Decryption Failed", username: "Error", password: "" };
                    }
                })
            );
            setItems(decryptedItems);
        } catch (e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    };

    const loadProfile = async () => {
        try {
            const res = await api.get<{ user: { hasRecovery: boolean; is2faEnabled: boolean } }>("/auth/me");
            setHasRecovery(res.data.user?.hasRecovery || false);
            setIs2faEnabled(res.data.user?.is2faEnabled || false);
        } catch (e) {
            console.error("Failed to load profile", e);
        }
    };

    useEffect(() => {
        loadItems();
        loadProfile();
    }, []);

    // Analyze password on change
    useEffect(() => {
        setStrength(analyzePasswordStrength(password));
    }, [password]);

    const handleAdd = async (e: React.FormEvent) => {
        e.preventDefault();

        if (password.length < 8) {
            alert("Password must be at least 8 characters long for security.");
            return;
        }

        try {
            const dataToEncrypt = JSON.stringify({ site, username, password });
            const { ciphertext, iv, authTag } = await EncryptionService.encrypt(dataToEncrypt);

            await api.post("/vault", {
                encryptedBlob: ciphertext,
                iv: iv,
                authTag: authTag,
            });

            setSite("");
            setUsername("");
            setPassword("");
            loadItems();
        } catch (e: any) {
            console.error("Save Error:", e);
            const errorMessage = e.response?.data?.error || e.message || "Failed to save item";
            alert(`Error: ${errorMessage}`);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm("Delete this password permanently?")) return;
        await api.delete(`/vault/${id}`);
        loadItems();
    };

    const handleEditClick = (item: any) => {
        setEditingItem(item);
        setEditSite(item.site);
        setEditUsername(item.username);
        setEditPassword(item.password);
        setShowEditPassword(false);
    };

    const handleUpdate = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!editingItem) return;

        if (editPassword.length < 8) {
            alert("Password must be at least 8 characters long for security.");
            return;
        }

        try {
            const dataToEncrypt = JSON.stringify({ site: editSite, username: editUsername, password: editPassword });
            const { ciphertext, iv, authTag } = await EncryptionService.encrypt(dataToEncrypt);

            await api.put(`/vault/${editingItem.id}`, {
                encryptedBlob: ciphertext,
                iv: iv,
                authTag: authTag,
            });

            setEditingItem(null);
            loadItems();
        } catch (e: any) {
            console.error("Update Error:", e);
            const errorMessage = e.response?.data?.error || e.message || "Failed to update item";
            alert(`Error: ${errorMessage}`);
        }
    };

    const openDeleteModal = () => {
        setDeletePassword("");
        setDeleteTotp("");
        setDeleteStep(1);
        setIsDeleteModalOpen(true);
    };

    const handleDeleteAccount = async () => {
        setIsDeleting(true);
        try {
            await api.request({
                method: "DELETE",
                url: "/auth/delete",
                data: { password: deletePassword, totpToken: deleteTotp }
            });
            onLogout();
        } catch (e: any) {
            alert(e.response?.data?.error || "Failed to delete account");
            setIsDeleting(false);
        }
    };

    const copyToClipboard = (text: string, id: string) => {
        navigator.clipboard.writeText(text);
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
    };

    const handleSetupRecovery = () => {
        setIsRecoveryModalOpen(true);
    };

    return (
        <div className="w-full max-w-6xl p-6 lg:p-12">
            {/* Header */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-12 gap-4">
                <div>
                    <h2 className="text-3xl font-bold text-white tracking-tight">Access Vault</h2>
                    <p className="text-slate-400 mt-1">Manage your secure credentials</p>
                </div>
                <div className="flex gap-3">
                    <button
                        onClick={openDeleteModal}
                        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors text-sm font-medium border border-red-500/20"
                    >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                        Delete Account
                    </button>
                    <button
                        onClick={handleSetupRecovery}
                        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-colors text-sm font-medium border border-emerald-500/20"
                    >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        Setup Recovery
                    </button>
                    <button
                        onClick={onLogout}
                        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition-colors text-sm font-medium border border-slate-700"
                    >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                        </svg>
                        Logout
                    </button>
                </div>
            </div>

            <div className="grid lg:grid-cols-3 gap-8">
                {/* Add New Password Form */}
                <div className="lg:col-span-1">
                    <div className="bg-slate-800/50 backdrop-blur-xl border border-slate-700/50 p-6 rounded-2xl sticky top-8">
                        <h3 className="text-lg font-semibold mb-6 text-white flex items-center gap-2">
                            <span className="flex items-center justify-center w-8 h-8 rounded-lg bg-blue-500/10 text-blue-400">
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                                </svg>
                            </span>
                            Add New Entry
                        </h3>
                        <form onSubmit={handleAdd} className="space-y-4">
                            <div>
                                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 ml-1">Website</label>
                                <input
                                    type="text"
                                    value={site}
                                    onChange={(e) => setSite(e.target.value)}
                                    placeholder="e.g. Netflix"
                                    className="w-full px-4 py-2.5 bg-slate-900 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 text-white placeholder-slate-600 outline-none transition-all"
                                    required
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 ml-1">Username</label>
                                <input
                                    type="text"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    placeholder="email@example.com"
                                    className="w-full px-4 py-2.5 bg-slate-900 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 text-white placeholder-slate-600 outline-none transition-all"
                                    required
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 ml-1">Password</label>
                                <div className="relative">
                                    <input
                                        type={showPasswordAdd ? "text" : "password"}
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        placeholder="Secure password"
                                        className="w-full px-4 py-2.5 bg-slate-900 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 text-white placeholder-slate-600 outline-none transition-all font-mono pr-20"
                                        required
                                    />
                                    <div className="absolute right-2 top-2 flex items-center gap-1">
                                        <button
                                            type="button"
                                            onClick={() => setShowPasswordAdd(!showPasswordAdd)}
                                            className="p-1 text-slate-500 hover:text-white rounded transition-colors"
                                        >
                                            {showPasswordAdd ? (
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
                                        <button
                                            type="button"
                                            onClick={() => setPassword("Gen" + Math.random().toString(36).slice(-10) + "!" + Math.floor(Math.random() * 100))}
                                            className="p-1 text-xs bg-slate-800 text-slate-400 hover:text-white rounded border border-slate-700"
                                        >
                                            Gen
                                        </button>
                                    </div>
                                </div>

                                {/* Password Strength Meter */}
                                {password && (
                                    <div className="mt-2 space-y-1">
                                        <div className="flex justify-between items-center text-xs">
                                            <span className="text-slate-400">Strength: <span className="text-white font-medium">{strength.label}</span></span>
                                            <span className="text-slate-500">{password.length} chars</span>
                                        </div>
                                        <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                                            <div
                                                className={`h-full transition-all duration-300 ${strength.color}`}
                                                style={{ width: `${(strength.score / 4) * 100}%` }}
                                            />
                                        </div>
                                        {strength.feedback.length > 0 && (
                                            <p className="text-[10px] text-slate-500 leading-tight">
                                                Tip: {strength.feedback[0]}
                                            </p>
                                        )}
                                    </div>
                                )}
                            </div>

                            <button type="submit" className="w-full mt-2 bg-blue-600 hover:bg-blue-500 text-white py-3 rounded-xl font-medium transition-colors shadow-lg shadow-blue-900/20">
                                Encrypt & Save
                            </button>
                        </form>
                    </div>
                </div>

                {/* Password List */}
                <div className="lg:col-span-2">
                    {loading ? (
                        <div className="flex flex-col items-center justify-center py-20 text-slate-500 animate-pulse">
                            <div className="w-12 h-12 border-4 border-slate-700 border-t-blue-500 rounded-full animate-spin mb-4"></div>
                            <p>Decrypting vault contents...</p>
                        </div>
                    ) : items.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-20 border-2 border-dashed border-slate-800 rounded-2xl bg-slate-900/30">
                            <svg className="w-16 h-16 text-slate-700 mb-4 opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                            </svg>
                            <p className="text-slate-500 font-medium">Your vault is empty</p>
                            <p className="text-slate-600 text-sm mt-1">Add your first secure credential to get started</p>
                        </div>
                    ) : (
                        <div className="grid gap-4">
                            {items.map((item) => (
                                <div key={item.id} className="group bg-slate-800/40 hover:bg-slate-800/80 backdrop-blur-sm border border-slate-700/50 hover:border-blue-500/30 p-5 rounded-2xl transition-all duration-200">
                                    <div className="flex items-start justify-between">
                                        <div className="flex items-center gap-4">
                                            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-slate-700 to-slate-800 flex items-center justify-center text-xl font-bold text-white border border-slate-600/50 shadow-inner">
                                                {item.site.charAt(0).toUpperCase()}
                                            </div>
                                            <div>
                                                <h4 className="text-lg font-semibold text-white">{item.site}</h4>
                                                <p className="text-slate-400 text-sm">{item.username}</p>
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => handleDelete(item.id)}
                                            className="opacity-0 group-hover:opacity-100 p-2 text-slate-500 hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-all"
                                            title="Delete Password"
                                        >
                                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                            </svg>
                                        </button>
                                    </div>

                                    <div className="mt-4 pt-4 border-t border-slate-700/50 flex items-center justify-between">
                                        <div className="flex-1 mr-4">
                                            <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-1">Password</p>
                                            <div className="flex gap-2">
                                                <div
                                                    onClick={() => copyToClipboard(item.password, item.id)}
                                                    className="flex-1 font-mono text-sm bg-slate-950/50 text-emerald-400 px-3 py-2 rounded-lg cursor-pointer hover:bg-black/40 transition-colors flex items-center justify-between group/pass"
                                                >
                                                    <span className="truncate mr-2">{item.password.replace(/./g, '•')}</span>
                                                    <span className="text-xs text-slate-500 group-hover/pass:text-white transition-colors">
                                                        {copiedId === item.id ? "Copied!" : "Click to Copy"}
                                                    </span>
                                                </div>
                                                <button
                                                    onClick={() => handleEditClick(item)}
                                                    className="px-3 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 transition-colors"
                                                    title="Edit Password"
                                                >
                                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                                                    </svg>
                                                </button>
                                            </div>
                                        </div>
                                        <div className="text-right ml-2">
                                            <p className="text-xs text-slate-600">Added</p>
                                            <p className="text-xs text-slate-500">{new Date(item.createdAt).toLocaleDateString()}</p>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            {/* Delete Account Modal */}
            {isDeleteModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
                    <div className="w-full max-w-md bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-200">
                        <div className="p-6">
                            <div className="flex items-center justify-between mb-6">
                                <h3 className="text-xl font-bold text-white">Delete Account</h3>
                                <button
                                    onClick={() => setIsDeleteModalOpen(false)}
                                    className="text-slate-400 hover:text-white transition-colors"
                                >
                                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                </button>
                            </div>

                            {deleteStep === 1 && (
                                <div className="space-y-4">
                                    <p className="text-slate-400 text-sm">
                                        Please enter your Master Password to proceed with account deletion.
                                    </p>
                                    <div>
                                        <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 ml-1">Master Password</label>
                                        <div className="relative">
                                            <input
                                                type={showPasswordDelete ? "text" : "password"}
                                                value={deletePassword}
                                                onChange={(e) => setDeletePassword(e.target.value)}
                                                className="w-full px-4 py-2.5 bg-slate-800 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 text-white placeholder-slate-600 outline-none transition-all pr-10"
                                                placeholder="Enter password"
                                                autoFocus
                                            />
                                            <button
                                                type="button"
                                                onClick={() => setShowPasswordDelete(!showPasswordDelete)}
                                                className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300 transition-colors"
                                            >
                                                {showPasswordDelete ? (
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
                                    </div>
                                    <div className="flex justify-end gap-3 pt-2">
                                        <button
                                            onClick={() => setIsDeleteModalOpen(false)}
                                            className="px-4 py-2 rounded-lg text-slate-300 hover:bg-slate-800 transition-colors font-medium text-sm"
                                            disabled={isDeleting}
                                        >
                                            Cancel
                                        </button>
                                        <button
                                            onClick={async () => {
                                                if (deletePassword) {
                                                    setIsDeleting(true);
                                                    try {
                                                        const res = await api.post<{ isValid: boolean }>("/auth/verify-password", { password: deletePassword });
                                                        if (res.data.isValid) {
                                                            setDeleteStep(2);
                                                        } else {
                                                            alert("Incorrect Password");
                                                        }
                                                    } catch (e: any) {
                                                        alert(e.response?.data?.error || "Failed to verify password");
                                                    } finally {
                                                        setIsDeleting(false);
                                                    }
                                                }
                                            }}
                                            disabled={!deletePassword || isDeleting}
                                            className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                                        >
                                            {isDeleting ? "Verifying..." : "Next"}
                                        </button>
                                    </div>
                                </div>
                            )}

                            {deleteStep === 2 && (
                                <div className="space-y-4">
                                    {is2faEnabled ? (
                                        <>
                                            <div>
                                                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 ml-1">Authenticator Code (2FA)</label>
                                                <input
                                                    type="text"
                                                    value={deleteTotp}
                                                    onChange={(e) => setDeleteTotp(e.target.value.replace(/[^0-9]/g, ''))}
                                                    className="w-full px-4 py-2.5 bg-slate-800 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 text-white placeholder-slate-600 outline-none transition-all tracking-widest text-center"
                                                    placeholder="000000"
                                                    maxLength={6}
                                                    autoFocus
                                                />
                                            </div>
                                            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl flex gap-3">
                                                <svg className="w-6 h-6 text-red-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                                </svg>
                                                <div className="space-y-1">
                                                    <p className="text-red-400 font-semibold text-sm">Final Confirmation</p>
                                                    <p className="text-red-400/80 text-xs leading-relaxed">
                                                        This action is irreversible. Valid TOTP required.
                                                    </p>
                                                </div>
                                            </div>
                                        </>
                                    ) : (
                                        <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl flex gap-3">
                                            <svg className="w-6 h-6 text-red-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                            </svg>
                                            <div className="space-y-1">
                                                <p className="text-red-400 font-semibold text-sm">Final Confirmation</p>
                                                <p className="text-red-400/80 text-xs leading-relaxed">
                                                    This action is irreversible. All your encrypted passwords and vault data will be permanently deleted.
                                                </p>
                                            </div>
                                        </div>
                                    )}

                                    <div className="flex justify-end gap-3 pt-2">
                                        <button
                                            onClick={() => setDeleteStep(1)}
                                            className="px-4 py-2 rounded-lg text-slate-300 hover:bg-slate-800 transition-colors font-medium text-sm"
                                            disabled={isDeleting}
                                        >
                                            Back
                                        </button>
                                        <button
                                            onClick={handleDeleteAccount}
                                            disabled={isDeleting || (is2faEnabled && deleteTotp.length !== 6)}
                                            className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-medium text-sm transition-colors shadow-lg shadow-red-900/20 flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                                        >
                                            {isDeleting ? (
                                                <>
                                                    <svg className="animate-spin w-4 h-4 text-white" fill="none" viewBox="0 0 24 24">
                                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                                    </svg>
                                                    Deleting...
                                                </>
                                            ) : (
                                                "Confirm & Delete"
                                            )}
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )
            }

            {/* Recovery Setup Modal */}
            {
                isRecoveryModalOpen && (
                    <RecoverySetup onClose={() => setIsRecoveryModalOpen(false)} />
                )
            }

            {/* Edit Modal */}
            {
                editingItem && (
                    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
                        <div className="w-full max-w-md bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-200">
                            <div className="p-6">
                                <div className="flex items-center justify-between mb-6">
                                    <h3 className="text-xl font-bold text-white">Edit Entry</h3>
                                    <button
                                        onClick={() => setEditingItem(null)}
                                        className="text-slate-400 hover:text-white transition-colors"
                                    >
                                        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                        </svg>
                                    </button>
                                </div>

                                <form onSubmit={handleUpdate} className="space-y-4">
                                    <div>
                                        <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 ml-1">Website</label>
                                        <input
                                            type="text"
                                            value={editSite}
                                            onChange={(e) => setEditSite(e.target.value)}
                                            className="w-full px-4 py-2.5 bg-slate-800 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 text-white placeholder-slate-600 outline-none transition-all"
                                            required
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 ml-1">Username</label>
                                        <input
                                            type="text"
                                            value={editUsername}
                                            onChange={(e) => setEditUsername(e.target.value)}
                                            className="w-full px-4 py-2.5 bg-slate-800 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 text-white placeholder-slate-600 outline-none transition-all"
                                            required
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 ml-1">Password</label>
                                        <div className="relative">
                                            <input
                                                type={showEditPassword ? "text" : "password"}
                                                value={editPassword}
                                                onChange={(e) => setEditPassword(e.target.value)}
                                                className="w-full px-4 py-2.5 bg-slate-800 border border-slate-700 rounded-xl focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 text-white placeholder-slate-600 outline-none transition-all font-mono pr-20"
                                                required
                                            />
                                            <div className="absolute right-2 top-2 flex items-center gap-1">
                                                <button
                                                    type="button"
                                                    onClick={() => setShowEditPassword(!showEditPassword)}
                                                    className="p-1 text-slate-500 hover:text-white rounded transition-colors"
                                                >
                                                    {showEditPassword ? (
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
                                                <button
                                                    type="button"
                                                    onClick={() => setEditPassword("Gen" + Math.random().toString(36).slice(-10) + "!" + Math.floor(Math.random() * 100))}
                                                    className="p-1 text-xs bg-slate-800 text-slate-400 hover:text-white rounded border border-slate-700"
                                                >
                                                    Gen
                                                </button>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="flex justify-end gap-3 pt-2">
                                        <button
                                            type="button"
                                            onClick={() => setEditingItem(null)}
                                            className="px-4 py-2 rounded-lg text-slate-300 hover:bg-slate-800 transition-colors font-medium text-sm"
                                        >
                                            Cancel
                                        </button>
                                        <button
                                            type="submit"
                                            className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm transition-colors shadow-lg shadow-blue-900/20"
                                        >
                                            Save Changes
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                )
            }
        </div >
    );

}
