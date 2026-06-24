"use client";

import { useEffect, useState } from "react";
import { api, VaultItem } from "../lib/api";
import { DecryptedVaultItem } from "@zk/shared";
import { EncryptionService } from "../utils/encryption.utils";
import { analyzePasswordStrength, StrengthResult } from "../utils/password-strength";
import RecoverySetup from "./auth/recovery-setup";

const CopyIcon = () => (
    <svg className="w-3.5 h-3.5 text-zinc-400 hover:text-white transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
    </svg>
);

const CheckIcon = () => (
    <svg className="w-3.5 h-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
    </svg>
);

const EyeIcon = () => (
    <svg className="w-3.5 h-3.5 text-zinc-400 hover:text-white transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
    </svg>
);

const EyeOffIcon = () => (
    <svg className="w-3.5 h-3.5 text-zinc-400 hover:text-white transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
    </svg>
);

const getAvatarColorClass = (char: string) => {
    const colors: Record<string, string> = {
        A: "bg-emerald-950/40 border-emerald-800/60 text-emerald-400",
        B: "bg-emerald-950/40 border-emerald-800/60 text-emerald-400",
        C: "bg-cyan-950/40 border-cyan-800/60 text-cyan-400",
        D: "bg-fuchsia-950/40 border-fuchsia-800/60 text-fuchsia-400",
        E: "bg-amber-950/40 border-amber-800/60 text-amber-400",
        F: "bg-red-950/40 border-red-800/60 text-red-400",
        G: "bg-teal-950/40 border-teal-800/60 text-teal-400",
        H: "bg-indigo-950/40 border-indigo-800/60 text-indigo-400",
        I: "bg-blue-950/40 border-blue-800/60 text-blue-400",
        J: "bg-rose-950/40 border-rose-800/60 text-rose-400",
        K: "bg-emerald-950/40 border-emerald-800/60 text-emerald-400",
        L: "bg-sky-950/40 border-sky-800/60 text-sky-400",
        M: "bg-cyan-950/40 border-cyan-800/60 text-cyan-400",
        N: "bg-indigo-950/40 border-indigo-800/60 text-indigo-400",
        O: "bg-amber-950/40 border-amber-800/60 text-amber-400",
        P: "bg-fuchsia-950/40 border-fuchsia-800/60 text-fuchsia-400",
        Q: "bg-teal-950/40 border-teal-800/60 text-teal-400",
        R: "bg-red-950/40 border-red-800/60 text-red-400",
        S: "bg-blue-950/40 border-blue-800/60 text-blue-400",
        T: "bg-indigo-950/40 border-indigo-800/60 text-indigo-400",
        U: "bg-sky-950/40 border-sky-800/60 text-sky-400",
        V: "bg-rose-950/40 border-rose-800/60 text-rose-400",
        W: "bg-emerald-950/40 border-emerald-800/60 text-emerald-400",
        X: "bg-teal-950/40 border-teal-800/60 text-teal-400",
        Y: "bg-cyan-950/40 border-cyan-800/60 text-cyan-400",
        Z: "bg-indigo-950/40 border-indigo-800/60 text-indigo-400"
    };
    const defaultColor = "bg-zinc-900 border-zinc-800 text-zinc-300";
    const upperChar = char.toUpperCase();
    return colors[upperChar] || defaultColor;
};

export default function VaultDashboard({ onLogout }: { onLogout: () => void }) {
    const [items, setItems] = useState<DecryptedVaultItem[]>([]);
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

    // Error States
    const [addError, setAddError] = useState("");
    const [editError, setEditError] = useState("");
    const [deleteItemError, setDeleteItemError] = useState("");
    const [deleteAccountError, setDeleteAccountError] = useState("");

    const [showPasswordAdd, setShowPasswordAdd] = useState(false);
    const [showPasswordDelete, setShowPasswordDelete] = useState(false);

    // Recovery State
    const [isRecoveryModalOpen, setIsRecoveryModalOpen] = useState(false);
    const [recoveryConfiguredAt, setRecoveryConfiguredAt] = useState<string | null>(null);
    const [isRecoveryDetailsOpen, setIsRecoveryDetailsOpen] = useState(false);

    // Edit State
    const [editingItem, setEditingItem] = useState<DecryptedVaultItem | null>(null);
    const [editSite, setEditSite] = useState("");
    const [editUsername, setEditUsername] = useState("");
    const [editPassword, setEditPassword] = useState("");
    const [showEditPassword, setShowEditPassword] = useState(false);

    // Strength State
    const [strength, setStrength] = useState<StrengthResult>({
        score: 0,
        label: "",
        color: "bg-zinc-700",
        feedback: []
    });

    const [searchTerm, setSearchTerm] = useState("");
    const [selectedItemId, setSelectedItemId] = useState<string | null>(null);
    const [currentUser, setCurrentUser] = useState("");
    const [showPasswordDetail, setShowPasswordDetail] = useState(false);
    const [isSettingsOpen, setIsSettingsOpen] = useState(false);

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
            const res = await api.get<{ user: { username: string; hasRecovery: boolean; is2faEnabled: boolean; recoveryConfiguredAt: string | null } }>("/auth/me");
            setHasRecovery(res.data.user?.hasRecovery || false);
            setIs2faEnabled(res.data.user?.is2faEnabled || false);
            setRecoveryConfiguredAt(res.data.user?.recoveryConfiguredAt || null);
            setCurrentUser(res.data.user?.username || "");
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
        setAddError("");

        if (password.length < 8) {
            setAddError("Password must be at least 8 characters long for security.");
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
            setAddError(errorMessage);
        }
    };

    // Item Deletion State
    const [itemToDelete, setItemToDelete] = useState<string | null>(null);
    const [itemDeletePassword, setItemDeletePassword] = useState("");
    const [showItemDeletePassword, setShowItemDeletePassword] = useState(false);
    const [isItemDeleteModalOpen, setIsItemDeleteModalOpen] = useState(false);
    const [isItemDeleting, setIsItemDeleting] = useState(false);

    // ... existing state ...

    const handleDelete = (id: string) => {
        setItemToDelete(id);
        setItemDeletePassword("");
        setShowItemDeletePassword(false);
        setIsItemDeleteModalOpen(true);
    };

    const confirmItemDelete = async () => {
        if (!itemToDelete) return;
        setDeleteItemError("");
        if (!itemDeletePassword) {
            setDeleteItemError("Please enter your master password to confirm deletion.");
            return;
        }

        setIsItemDeleting(true);
        try {
            // 1. Verify Master Password
            const res = await api.post<{ isValid: boolean }>("/auth/verify-password", { password: itemDeletePassword });
            if (!res.data.isValid) {
                setDeleteItemError("Incorrect Master Password");
                setIsItemDeleting(false);
                return;
            }

            // 2. Delete Item
            await api.delete(`/vault/${itemToDelete}`);

            // 3. Cleanup
            loadItems();
            setIsItemDeleteModalOpen(false);
            setItemToDelete(null);
            setItemDeletePassword("");
        } catch (e: any) {
            console.error("Delete Error:", e);
            setDeleteItemError(e.response?.data?.error || "Failed to verify password or delete item");
        } finally {
            setIsItemDeleting(false);
        }
    };

    const handleEditClick = (item: DecryptedVaultItem) => {
        setEditingItem(item);
        setEditSite(item.site);
        setEditUsername(item.username);
        setEditPassword(item.password);
        setShowEditPassword(false);
    };

    const handleUpdate = async () => {
        if (!editingItem) return;
        setEditError("");

        if (editPassword.length < 8) {
            setEditError("Password must be at least 8 characters long for security.");
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
            setEditError(errorMessage);
        }
    };

    const openDeleteModal = () => {
        setDeleteAccountError("");
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
            setDeleteAccountError(e.response?.data?.error || "Failed to delete account");
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

    const selectedItem = items.find(item => item.id === selectedItemId) || null;
    const filteredItems = items.filter(item => 
        item.site.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.username.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="w-full h-full flex items-center justify-center overflow-hidden bg-[#0a0b0d] p-4">
        <div className="w-full max-w-[1100px] h-[calc(100vh-2rem)] max-h-[640px] flex flex-row overflow-hidden bg-[#111213] border border-zinc-800/70 rounded-xl">
            {/* Left Sidebar */}
            <div className="w-[195px] bg-[#111213] border-r border-zinc-800/60 p-5 flex flex-col justify-between shrink-0 h-full">
                <div className="space-y-5">
                    {/* ZK Vault Title and icon */}
                    <div className="flex items-center gap-2">
                        <svg className="w-5 h-5 text-zinc-200" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                        <div>
                            <h1 className="text-sm font-bold text-white tracking-tight">ZK Vault</h1>
                            <p className="text-[10px] text-zinc-500 font-medium">Zero-Knowledge Secure</p>
                        </div>
                    </div>

                    {/* Active Vault Card */}
                    <div className="p-3 bg-zinc-900/40 border border-zinc-800/60 rounded-lg space-y-1">
                        <span className="block text-[9px] font-semibold text-zinc-500 uppercase tracking-widest">Active Vault</span>
                        <span className="block text-base font-bold text-zinc-100 truncate">{currentUser || "loading..."}</span>
                        <div className="flex items-center gap-1.5 mt-0.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-600"></span>
                            <span className="text-[10px] text-emerald-500 font-semibold">Synced</span>
                        </div>
                    </div>

                    {/* New Entry Button */}
                    <button
                        onClick={() => setSelectedItemId(null)}
                        className="w-full py-2.5 bg-emerald-800 hover:bg-emerald-700 text-emerald-100 rounded-lg text-xs font-bold transition-colors flex items-center justify-center gap-2 shadow-sm"
                    >
                        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 4v16m8-8H4" />
                        </svg>
                        New Entry
                    </button>

                    {/* Settings Link */}
                    <button
                        onClick={() => setIsSettingsOpen(true)}
                        className="w-full flex items-center justify-between py-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition-colors"
                    >
                        <div className="flex items-center gap-2">
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            </svg>
                            <span>Settings</span>
                        </div>
                        <svg className="w-3 h-3 text-zinc-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                    </button>
                </div>

                {/* Logout Button */}
                <button
                    onClick={onLogout}
                    className="w-full flex items-center gap-2 py-2 text-zinc-400 hover:text-zinc-200 transition-colors text-xs font-semibold"
                >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                    </svg>
                    Logout
                </button>
            </div>

            {/* Pane 2: Middle List Pane */}
            <div className="w-[280px] shrink-0 bg-[#111213] border-r border-zinc-800/60 flex flex-col overflow-hidden h-full">
                {/* Search Bar */}
                <div className="p-3 shrink-0">
                    <div className="relative flex items-center">
                        <svg className="absolute left-3 w-3.5 h-3.5 text-zinc-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                        </svg>
                        <input
                            type="text"
                            placeholder="Search credentials..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full pl-9 pr-12 py-2 bg-zinc-900/60 border border-zinc-700/60 text-white text-xs placeholder-zinc-500 rounded-lg focus:border-zinc-600 focus:outline-none outline-none transition-all font-sans"
                        />
                        <span className="absolute right-2.5 px-1.5 py-0.5 bg-zinc-800/80 border border-zinc-700/60 rounded text-[9px] font-mono text-zinc-500 select-none">
                            ⌘K
                        </span>
                    </div>
                </div>

                {/* List Items */}
                <div className="flex-1 overflow-y-auto px-2 pb-2 space-y-0.5">
                    {loading ? (
                        <div className="flex flex-col items-center justify-center py-20 text-zinc-500">
                            <div className="w-6 h-6 border-2 border-zinc-700 border-t-emerald-500 rounded-full animate-spin mb-3"></div>
                            <p className="text-[11px]">Decrypting vault...</p>
                        </div>
                    ) : filteredItems.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-16 text-center">
                            <svg className="w-8 h-8 text-zinc-700 mb-2 opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                            </svg>
                            <p className="text-zinc-500 text-[11px] font-medium">No items found</p>
                        </div>
                    ) : (
                        filteredItems.map((item) => {
                            const isSelected = selectedItemId === item.id;
                            const firstChar = item.site ? item.site.charAt(0) : "?";
                            return (
                                <div
                                    key={item.id}
                                    onClick={() => {
                                        setSelectedItemId(item.id);
                                        setShowPasswordDetail(false);
                                    }}
                                    className={`flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer transition-all ${
                                        isSelected
                                            ? "bg-zinc-800/60 border-l-2 border-l-emerald-700 pl-[10px]"
                                            : "hover:bg-zinc-800/30"
                                    }`}
                                >
                                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold shrink-0 ${getAvatarColorClass(firstChar)}`}>
                                        {firstChar.toUpperCase()}
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <h4 className="text-xs font-semibold text-zinc-100 truncate">{item.site}</h4>
                                        <p className="text-[10px] text-zinc-500 truncate">{item.username}</p>
                                    </div>
                                </div>
                            );
                        })
                    )}
                </div>

                {/* Footer Count */}
                <div className="px-4 py-3 border-t border-zinc-800/60 text-[10px] text-zinc-500 shrink-0 font-medium">
                    {filteredItems.length} {filteredItems.length === 1 ? "entry" : "entries"}
                </div>
            </div>

            {/* Pane 3: Right Details Panel */}
            <div className="flex-1 bg-[#111213] flex flex-col overflow-y-auto p-6 h-full">
                {selectedItem ? (
                    <div className="flex flex-col h-full">
                        {/* Header */}
                        <div className="flex items-center gap-3 mb-6">
                            <div className={`w-11 h-11 rounded-lg flex items-center justify-center text-sm font-bold shrink-0 ${getAvatarColorClass(editingItem?.id === selectedItem.id ? editSite.charAt(0) || "?" : (selectedItem.site ? selectedItem.site.charAt(0) : "?"))}`}>
                                {(editingItem?.id === selectedItem.id ? editSite.charAt(0) || "?" : (selectedItem.site ? selectedItem.site.charAt(0) : "?")).toUpperCase()}
                            </div>
                            <div className="min-w-0 flex-1">
                                {editingItem?.id === selectedItem.id ? (
                                    <p className="text-xs text-zinc-500">Editing entry</p>
                                ) : (
                                    <>
                                        <h3 className="text-base font-bold text-white truncate leading-tight">{selectedItem.site}</h3>
                                        <p className="text-xs text-zinc-500 mt-0.5">
                                            Credentials &bull; Updated {new Date(selectedItem.updatedAt).toLocaleDateString() === new Date().toLocaleDateString() ? "today" : new Date(selectedItem.updatedAt).toLocaleDateString()}
                                        </p>
                                    </>
                                )}
                            </div>
                        </div>

                        {/* Details Fields */}
                        <div className="space-y-5 flex-1">
                            {/* Website Field */}
                            <div className="space-y-1.5">
                                <span className="block text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">Website</span>
                                {editingItem?.id === selectedItem.id ? (
                                    <input
                                        type="text"
                                        value={editSite}
                                        onChange={(e) => setEditSite(e.target.value)}
                                        className="w-full px-3 py-2.5 bg-zinc-900/80 border border-zinc-600 rounded-lg text-sm text-white focus:border-zinc-500 focus:outline-none transition-all"
                                        autoFocus
                                    />
                                ) : (
                                    <div className="bg-zinc-900/50 border border-zinc-700/60 rounded-lg px-3 py-2.5 flex items-center justify-between gap-2">
                                        <span className="text-sm text-zinc-200 select-all truncate flex-1">
                                            {selectedItem.site}
                                        </span>
                                        <button
                                            onClick={() => copyToClipboard(selectedItem.site, `site-${selectedItem.id}`)}
                                            className="p-1 text-zinc-500 hover:text-zinc-300 rounded transition-colors shrink-0"
                                            title="Copy Website"
                                        >
                                            {copiedId === `site-${selectedItem.id}` ? <CheckIcon /> : <CopyIcon />}
                                        </button>
                                    </div>
                                )}
                            </div>

                            {/* Username Field */}
                            <div className="space-y-1.5">
                                <span className="block text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">Username / Email</span>
                                {editingItem?.id === selectedItem.id ? (
                                    <input
                                        type="text"
                                        value={editUsername}
                                        onChange={(e) => setEditUsername(e.target.value)}
                                        className="w-full px-3 py-2.5 bg-zinc-900/80 border border-zinc-600 rounded-lg text-sm text-white focus:border-zinc-500 focus:outline-none transition-all"
                                    />
                                ) : (
                                    <div className="bg-zinc-900/50 border border-zinc-700/60 rounded-lg px-3 py-2.5 flex items-center justify-between gap-2">
                                        <span className="text-sm text-zinc-200 select-all truncate flex-1">
                                            {selectedItem.username}
                                        </span>
                                        <button
                                            onClick={() => copyToClipboard(selectedItem.username, `user-${selectedItem.id}`)}
                                            className="p-1 text-zinc-500 hover:text-zinc-300 rounded transition-colors shrink-0"
                                            title="Copy Username"
                                        >
                                            {copiedId === `user-${selectedItem.id}` ? <CheckIcon /> : <CopyIcon />}
                                        </button>
                                    </div>
                                )}
                            </div>

                            {/* Password Field */}
                            <div className="space-y-1.5">
                                <span className="block text-[10px] font-semibold text-zinc-500 uppercase tracking-widest">Password</span>
                                {editingItem?.id === selectedItem.id ? (
                                    <div className="relative">
                                        <input
                                            type={showEditPassword ? "text" : "password"}
                                            value={editPassword}
                                            onChange={(e) => setEditPassword(e.target.value)}
                                            className="w-full pl-3 pr-20 py-2.5 bg-zinc-900/80 border border-zinc-600 rounded-lg text-sm text-white font-mono focus:border-zinc-500 focus:outline-none transition-all"
                                        />
                                        <div className="absolute right-2 top-2 flex items-center gap-1">
                                            <button
                                                type="button"
                                                onClick={() => setShowEditPassword(!showEditPassword)}
                                                className="p-1 text-zinc-500 hover:text-white rounded transition-colors"
                                            >
                                                {showEditPassword ? <EyeOffIcon /> : <EyeIcon />}
                                            </button>
                                            <button
                                                type="button"
                                                onClick={() => setEditPassword("Gen" + Math.random().toString(36).slice(-10) + "!" + Math.floor(Math.random() * 100))}
                                                className="px-1.5 py-0.5 text-[9px] bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded border border-zinc-700 transition-colors"
                                            >
                                                Gen
                                            </button>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="bg-zinc-900/50 border border-zinc-700/60 rounded-lg px-3 py-2.5 flex items-center justify-between gap-2">
                                        {showPasswordDetail ? (
                                            <span className="text-sm text-zinc-200 font-mono select-all truncate flex-1">
                                                {selectedItem.password}
                                            </span>
                                        ) : (
                                            <span className="text-base text-emerald-600 tracking-[0.18em] font-bold select-none truncate flex-1">
                                                {"●".repeat(Math.min(selectedItem.password.length, 16))}
                                            </span>
                                        )}
                                        <div className="flex items-center gap-1.5 shrink-0">
                                            <button
                                                type="button"
                                                onClick={() => setShowPasswordDetail(!showPasswordDetail)}
                                                className="p-1 text-zinc-500 hover:text-zinc-300 rounded transition-colors"
                                                title={showPasswordDetail ? "Hide Password" : "Show Password"}
                                            >
                                                {showPasswordDetail ? <EyeOffIcon /> : <EyeIcon />}
                                            </button>
                                            <button
                                                onClick={() => copyToClipboard(selectedItem.password, selectedItem.id)}
                                                className="p-1 text-zinc-500 hover:text-zinc-300 rounded transition-colors"
                                                title="Copy Password"
                                            >
                                                {copiedId === selectedItem.id ? <CheckIcon /> : <CopyIcon />}
                                            </button>
                                        </div>
                                    </div>
                                )}

                                {/* Strength Indicator */}
                                {(() => {
                                    const pwd = editingItem?.id === selectedItem.id ? editPassword : selectedItem.password;
                                    const itemStrength = analyzePasswordStrength(pwd);
                                    return (
                                        <div className="flex items-center gap-1.5 mt-1.5 px-0.5">
                                            <svg className={`w-3.5 h-3.5 ${itemStrength.score >= 3 ? "text-emerald-500" : "text-zinc-500"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                {itemStrength.score >= 3 ? (
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                                ) : (
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                                )}
                                            </svg>
                                            <span className={`text-xs font-semibold ${itemStrength.score >= 3 ? "text-emerald-500" : "text-zinc-400"}`}>
                                                {itemStrength.label}
                                            </span>
                                            <span className="text-xs text-zinc-500">&bull; {pwd.length} characters</span>
                                        </div>
                                    );
                                })()}
                            </div>

                            {/* Edit error */}
                            {editingItem?.id === selectedItem.id && editError && (
                                <div className="p-2.5 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-lg flex items-center gap-1.5">
                                    <svg className="w-3.5 h-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    {editError}
                                </div>
                            )}
                        </div>

                        {/* Action Buttons */}
                        {editingItem?.id === selectedItem.id ? (
                            <div className="flex gap-3 mt-8">
                                <button
                                    type="button"
                                    onClick={() => { setEditingItem(null); setEditError(""); }}
                                    className="flex-1 py-2.5 bg-zinc-800/60 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 rounded-lg text-sm font-semibold transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={() => handleUpdate()}
                                    className="flex-1 py-2.5 bg-emerald-800 hover:bg-emerald-700 text-emerald-100 rounded-lg text-sm font-semibold transition-colors"
                                >
                                    Save Changes
                                </button>
                            </div>
                        ) : (
                            <div className="flex gap-3 mt-8">
                                <button
                                    onClick={() => handleEditClick(selectedItem)}
                                    className="flex-1 py-2.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 hover:text-white rounded-lg text-sm font-semibold transition-colors flex items-center justify-center gap-2"
                                >
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                                    </svg>
                                    Edit
                                </button>
                                <button
                                    onClick={() => handleDelete(selectedItem.id)}
                                    className="flex-1 py-2.5 bg-red-900/60 hover:bg-red-800/70 text-red-300 hover:text-red-200 rounded-lg text-sm font-semibold transition-colors flex items-center justify-center gap-2"
                                >
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                    </svg>
                                    Delete
                                </button>
                            </div>
                        )}
                    </div>
                ) : (
                    <div className="space-y-4">
                        <h3 className="text-xs font-bold text-white pb-3 border-b border-zinc-800/80 uppercase tracking-wider">Add New Entry</h3>
                        <form onSubmit={handleAdd} className="space-y-3.5">
                            <div className="space-y-1">
                                <label className="block text-[9px] font-semibold text-zinc-500 uppercase tracking-wider">Website / App Name</label>
                                <input
                                    type="text"
                                    value={site}
                                    onChange={(e) => setSite(e.target.value)}
                                    placeholder="e.g. Netflix"
                                    className="w-full px-3 py-2 bg-zinc-950/40 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-xs placeholder-zinc-600 transition-all font-sans"
                                    required
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="block text-[9px] font-semibold text-zinc-500 uppercase tracking-wider">Username / Email</label>
                                <input
                                    type="text"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    placeholder="email@example.com"
                                    className="w-full px-3 py-2 bg-zinc-950/40 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-xs placeholder-zinc-600 transition-all font-sans"
                                    required
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="block text-[9px] font-semibold text-zinc-500 uppercase tracking-wider">Password</label>
                                <div className="relative">
                                    <input
                                        type={showPasswordAdd ? "text" : "password"}
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        placeholder="Secure password"
                                        className="w-full pl-3 pr-20 py-2 bg-zinc-950/40 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-xs placeholder-zinc-650 transition-all font-mono"
                                        required
                                    />
                                    <div className="absolute right-2 top-1.5 flex items-center gap-1">
                                        <button
                                            type="button"
                                            onClick={() => setShowPasswordAdd(!showPasswordAdd)}
                                            className="p-1 text-zinc-500 hover:text-white rounded transition-colors"
                                        >
                                            {showPasswordAdd ? (
                                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                                                </svg>
                                            ) : (
                                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                                </svg>
                                            )}
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => setPassword("Gen" + Math.random().toString(36).slice(-10) + "!" + Math.floor(Math.random() * 100))}
                                            className="px-1.5 py-0.5 text-[9px] bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded border border-zinc-700 transition-colors"
                                        >
                                            Gen
                                        </button>
                                    </div>
                                </div>
                                {password && (
                                    <div className="mt-1.5 space-y-1">
                                        <div className="flex justify-between items-center text-[10px]">
                                            <span className="text-zinc-500">Strength: <span className="text-zinc-300 font-medium">{strength.label}</span></span>
                                            <span className="text-zinc-500">{password.length} chars</span>
                                        </div>
                                        <div className="h-1 w-full bg-zinc-950 border border-zinc-800 rounded-full overflow-hidden">
                                            <div
                                                className={`h-full transition-all duration-300 ${strength.color}`}
                                                style={{ width: `${(strength.score / 4) * 100}%` }}
                                            />
                                        </div>
                                    </div>
                                )}
                            </div>

                            {addError && (
                                <div className="p-2.5 bg-red-500/10 border border-red-500/20 text-red-400 text-[10px] rounded flex items-center gap-1.5 font-sans">
                                    <svg className="w-3.5 h-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    {addError}
                                </div>
                            )}

                            <button
                                type="submit"
                                className="w-full mt-2 bg-emerald-800 hover:bg-emerald-700 text-emerald-100 py-2 rounded text-xs font-semibold transition-colors"
                            >
                                Encrypt & Save
                            </button>
                        </form>
                    </div>
                )}
            </div>
        </div>

            {/* Settings Modal */}
            {isSettingsOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
                    <div className="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl overflow-hidden">
                        <div className="p-5">
                            <div className="flex items-center justify-between mb-4 pb-2 border-b border-zinc-800">
                                <h3 className="text-xs font-bold text-white uppercase tracking-wider">Account Settings</h3>
                                <button
                                    onClick={() => setIsSettingsOpen(false)}
                                    className="text-zinc-500 hover:text-white transition-colors"
                                >
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                </button>
                            </div>

                            <div className="space-y-4">
                                <div className="space-y-1">
                                    <span className="block text-[8px] font-semibold text-zinc-500 uppercase tracking-wider ml-0.5">Active Vault User</span>
                                    <div className="px-2.5 py-1.5 bg-zinc-950 border border-zinc-800 rounded text-xs text-zinc-300 font-mono truncate">
                                        {currentUser || "loading..."}
                                    </div>
                                </div>

                                <div className="space-y-2">
                                    <span className="block text-[8px] font-semibold text-zinc-500 uppercase tracking-wider ml-0.5">Security Settings</span>
                                    <div className="p-3 bg-zinc-950 border border-zinc-800 rounded space-y-3">
                                        <div className="flex items-center justify-between text-xs">
                                            <span className="text-zinc-400">Two-Factor Authentication (2FA)</span>
                                            <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold ${is2faEnabled ? "bg-emerald-500/10 text-emerald-450 text-emerald-400 border border-emerald-500/20" : "bg-zinc-800 text-zinc-400"}`}>
                                                {is2faEnabled ? "Enabled" : "Disabled"}
                                            </span>
                                        </div>

                                        <div className="flex items-center justify-between text-xs pt-2.5 border-t border-zinc-900">
                                            <span className="text-zinc-400">Recovery Status</span>
                                            <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold ${hasRecovery ? "bg-emerald-500/10 text-emerald-450 text-emerald-400 border border-emerald-500/20" : "bg-zinc-800 text-zinc-400"}`}>
                                                {hasRecovery ? "Active" : "Not Setup"}
                                            </span>
                                        </div>

                                        <div className="pt-1 flex gap-2">
                                            {!hasRecovery ? (
                                                <button
                                                    onClick={() => {
                                                        setIsSettingsOpen(false);
                                                        handleSetupRecovery();
                                                    }}
                                                    className="w-full text-center px-3 py-1.5 rounded text-xs font-semibold text-emerald-455 text-emerald-400 bg-emerald-500/5 hover:bg-emerald-500/10 border border-emerald-500/10 transition-colors"
                                                >
                                                    Setup Recovery Key
                                                </button>
                                            ) : (
                                                <button
                                                    onClick={() => {
                                                        setIsSettingsOpen(false);
                                                        setIsRecoveryDetailsOpen(true);
                                                    }}
                                                    className="w-full text-center px-3 py-1.5 rounded text-xs font-semibold text-emerald-455 text-emerald-400 bg-emerald-500/5 hover:bg-emerald-500/10 border border-emerald-500/10 transition-colors"
                                                >
                                                    View Recovery Status
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                </div>

                                <div className="space-y-2 pt-2 border-t border-zinc-800">
                                    <span className="block text-[8px] font-semibold text-red-500 uppercase tracking-wider ml-0.5">Danger Zone</span>
                                    <div className="p-3 bg-red-500/5 border border-red-950/40 rounded flex flex-col gap-2.5">
                                        <p className="text-red-400/80 text-[10px] leading-relaxed">
                                            Permanently delete your vault and all encrypted data. This action is irreversible.
                                        </p>
                                        <button
                                            onClick={() => {
                                                setIsSettingsOpen(false);
                                                openDeleteModal();
                                            }}
                                            className="w-full text-center px-3 py-1.5 rounded bg-red-600 hover:bg-red-505 hover:bg-red-500 text-white font-semibold text-xs transition-colors"
                                        >
                                            Delete Account
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <div className="flex justify-end mt-4">
                                <button
                                    onClick={() => setIsSettingsOpen(false)}
                                    className="px-3.5 py-1.5 bg-zinc-950 hover:bg-zinc-800 border border-zinc-800 text-zinc-300 rounded text-xs font-semibold transition-colors"
                                >
                                    Close
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Delete Account Modal */}
            {isDeleteModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
                    <div className="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl overflow-hidden">
                        <div className="p-5">
                            <div className="flex items-center justify-between mb-4 pb-2 border-b border-zinc-800">
                                <h3 className="text-xs font-bold text-white uppercase tracking-wider">Delete Account</h3>
                                <button
                                    onClick={() => setIsDeleteModalOpen(false)}
                                    className="text-zinc-500 hover:text-white transition-colors"
                                >
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                </button>
                            </div>

                            {deleteStep === 1 && (
                                <div className="space-y-4">
                                    <p className="text-zinc-400 text-xs">
                                        Please enter your Master Password to proceed with account deletion.
                                    </p>
                                    <div className="space-y-1">
                                        <label className="block text-[8px] font-semibold text-zinc-500 uppercase tracking-wider ml-0.5">Master Password</label>
                                        <div className="relative">
                                            <input
                                                type={showPasswordDelete ? "text" : "password"}
                                                value={deletePassword}
                                                onChange={(e) => setDeletePassword(e.target.value)}
                                                className="w-full px-2.5 py-1.5 bg-zinc-950 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-xs pr-10"
                                                placeholder="Enter password"
                                                autoFocus
                                            />
                                            <button
                                                type="button"
                                                onClick={() => setShowPasswordDelete(!showPasswordDelete)}
                                                className="absolute right-3 top-2 text-zinc-500 hover:text-zinc-300 transition-colors"
                                            >
                                                {showPasswordDelete ? (
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

                                    {deleteAccountError && (
                                        <div className="p-2 bg-red-500/10 border border-red-500/20 text-red-400 text-[10px] rounded flex items-center gap-1.5">
                                            <svg className="w-3.5 h-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                            </svg>
                                            {deleteAccountError}
                                        </div>
                                    )}

                                    <div className="flex justify-end gap-2 pt-2">
                                        <button
                                            onClick={() => setIsDeleteModalOpen(false)}
                                            className="px-3.5 py-1.5 rounded text-zinc-400 hover:text-white transition-colors text-xs font-medium"
                                            disabled={isDeleting}
                                        >
                                            Cancel
                                        </button>
                                        <button
                                            onClick={async () => {
                                                if (deletePassword) {
                                                    setIsDeleting(true);
                                                    try {
                                                        setDeleteAccountError("");
                                                        const res = await api.post<{ isValid: boolean }>("/auth/verify-password", { password: deletePassword });
                                                        if (res.data.isValid) {
                                                            setDeleteStep(2);
                                                        } else {
                                                            setDeleteAccountError("Incorrect Password");
                                                        }
                                                    } catch (e: any) {
                                                        setDeleteAccountError(e.response?.data?.error || "Failed to verify password");
                                                    } finally {
                                                        setIsDeleting(false);
                                                    }
                                                }
                                            }}
                                            disabled={!deletePassword || isDeleting}
                                            className="px-3.5 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors disabled:opacity-50 flex items-center gap-2"
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
                                            <div className="space-y-1">
                                                <label className="block text-[8px] font-semibold text-zinc-500 uppercase tracking-wider ml-0.5">Authenticator Code (2FA)</label>
                                                <input
                                                    type="text"
                                                    value={deleteTotp}
                                                    onChange={(e) => setDeleteTotp(e.target.value.replace(/[^0-9]/g, ''))}
                                                    className="w-full px-2.5 py-1.5 bg-zinc-950 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-center text-sm font-mono tracking-widest"
                                                    placeholder="000000"
                                                    maxLength={6}
                                                    autoFocus
                                                />
                                            </div>
                                            <div className="p-3 bg-red-500/5 border border-red-950/40 rounded flex gap-2">
                                                <svg className="w-5 h-5 text-red-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                                </svg>
                                                <div className="space-y-0.5">
                                                    <p className="text-red-400 font-semibold text-xs">Final Confirmation</p>
                                                    <p className="text-red-400/80 text-[10px] leading-relaxed">
                                                        This action is irreversible. Valid TOTP required.
                                                    </p>
                                                </div>
                                            </div>
                                        </>
                                    ) : (
                                        <div className="p-3 bg-red-500/5 border border-red-950/40 rounded flex gap-2">
                                            <svg className="w-5 h-5 text-red-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                            </svg>
                                            <div className="space-y-0.5">
                                                <p className="text-red-400 font-semibold text-xs">Final Confirmation</p>
                                                <p className="text-red-400/80 text-[10px] leading-relaxed">
                                                    This action is irreversible. All your encrypted credentials and recovery key will be permanently deleted.
                                                </p>
                                            </div>
                                        </div>
                                    )}

                                    {deleteAccountError && (
                                        <div className="p-2 bg-red-500/5 border border-red-500/10 text-red-500 text-[10px] rounded flex items-center gap-1.5">
                                            <svg className="w-3.5 h-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                            </svg>
                                            {deleteAccountError}
                                        </div>
                                    )}

                                    <div className="flex justify-end gap-2 pt-2">
                                        <button
                                            onClick={() => setDeleteStep(1)}
                                            className="px-3.5 py-1.5 rounded text-zinc-400 hover:text-white transition-colors text-xs font-medium"
                                            disabled={isDeleting}
                                        >
                                            Back
                                        </button>
                                        <button
                                            onClick={handleDeleteAccount}
                                            disabled={isDeleting || (is2faEnabled && deleteTotp.length !== 6)}
                                            className="px-3.5 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white font-semibold text-xs transition-colors flex items-center gap-2 disabled:opacity-50"
                                        >
                                            {isDeleting ? "Deleting..." : "Confirm & Delete"}
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Recovery Setup Modal */}
            {isRecoveryModalOpen && (
                <RecoverySetup onClose={() => {
                    setIsRecoveryModalOpen(false);
                    loadProfile();
                }} />
            )}

            {/* Recovery Details Modal */}
            {isRecoveryDetailsOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
                    <div className="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl overflow-hidden">
                        <div className="p-5">
                            <div className="flex items-center justify-between mb-4 pb-2 border-b border-zinc-800">
                                <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                                    <svg className="w-4 h-4 text-emerald-450 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    Recovery Status
                                </h3>
                                <button
                                    onClick={() => setIsRecoveryDetailsOpen(false)}
                                    className="text-zinc-500 hover:text-white transition-colors"
                                >
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                </button>
                            </div>
                            <div className="space-y-3">
                                <div className="p-2.5 bg-zinc-950 border border-zinc-800 rounded space-y-0.5">
                                    <span className="block text-[8px] font-semibold text-zinc-500 uppercase tracking-wider">Status</span>
                                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[9px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                        Active & Valid
                                    </span>
                                </div>
                                <div className="p-2.5 bg-zinc-950 border border-zinc-800 rounded space-y-0.5">
                                    <span className="block text-[8px] font-semibold text-zinc-500 uppercase tracking-wider">Configured On</span>
                                    <span className="text-zinc-300 text-xs font-mono font-medium">
                                        {recoveryConfiguredAt ? new Date(recoveryConfiguredAt).toLocaleString(undefined, { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : "Legacy Configured (Date N/A)"}
                                    </span>
                                </div>
                                <div className="p-2.5 bg-emerald-500/5 border border-emerald-500/10 rounded">
                                    <p className="text-zinc-500 text-[10px] leading-relaxed">
                                        Recovery keys are single-use emergency credentials. Using the key to reset your master password consumes it, requiring you to configure a new key afterwards.
                                    </p>
                                </div>
                            </div>
                            <div className="flex justify-end mt-4">
                                <button
                                    onClick={() => setIsRecoveryDetailsOpen(false)}
                                    className="px-3.5 py-1.5 bg-zinc-950 hover:bg-zinc-800 border border-zinc-800 text-white rounded text-xs font-semibold transition-colors"
                                >
                                    Close
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Edit modal removed — editing is now inline in the right detail pane */}

            {/* Item Delete Modal */}
            {isItemDeleteModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
                    <div className="w-full max-w-md bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl overflow-hidden">
                        <div className="p-5">
                            <div className="flex items-center justify-between mb-4 pb-2 border-b border-zinc-800">
                                <h3 className="text-xs font-bold text-white uppercase tracking-wider">Delete Item</h3>
                                <button
                                    onClick={() => {
                                        setIsItemDeleteModalOpen(false);
                                        setItemToDelete(null);
                                        setItemDeletePassword("");
                                    }}
                                    className="text-zinc-500 hover:text-white transition-colors"
                                >
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                </button>
                            </div>

                            <p className="text-zinc-400 text-xs mb-4">
                                Are you sure you want to delete this item? This action cannot be undone.
                                Please enter your master password to confirm.
                            </p>

                            <div className="space-y-1 mb-4">
                                <label className="block text-[8px] font-semibold text-zinc-500 uppercase tracking-wider ml-0.5">Master Password</label>
                                <div className="relative">
                                    <input
                                        type={showItemDeletePassword ? "text" : "password"}
                                        value={itemDeletePassword}
                                        onChange={(e) => setItemDeletePassword(e.target.value)}
                                        className="w-full px-2.5 py-1.5 bg-zinc-950 border border-zinc-800 rounded focus:border-zinc-700 focus:outline-none outline-none text-white text-xs pr-10"
                                        placeholder="Enter Master Password"
                                        autoFocus
                                    />
                                    <button
                                        type="button"
                                        onClick={() => setShowItemDeletePassword(!showItemDeletePassword)}
                                        className="absolute right-3 top-2 text-zinc-500 hover:text-zinc-300 transition-colors"
                                    >
                                        {showItemDeletePassword ? (
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

                            {deleteItemError && (
                                <div className="mb-4 p-2 bg-red-500/10 border border-red-500/20 text-red-500 text-[10px] rounded flex items-center gap-1.5">
                                    <svg className="w-3.5 h-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    {deleteItemError}
                                </div>
                            )}

                            <div className="flex justify-end gap-2">
                                <button
                                    onClick={() => {
                                        setIsItemDeleteModalOpen(false);
                                        setItemToDelete(null);
                                        setItemDeletePassword("");
                                    }}
                                    className="px-3.5 py-1.5 rounded text-zinc-400 hover:text-white transition-colors text-xs font-medium"
                                    disabled={isItemDeleting}
                                >
                                    Cancel
                                </button>
                                <button
                                    className="px-3.5 py-1.5 rounded bg-red-650 hover:bg-red-500 text-white font-semibold text-xs transition-colors flex items-center gap-2"
                                    onClick={confirmItemDelete}
                                    disabled={isItemDeleting}
                                >
                                    {isItemDeleting ? "Verifying..." : "Delete Item"}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
