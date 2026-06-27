"use client";

import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";

function ConfirmationContent() {
    const searchParams = useSearchParams();
    const type = searchParams.get("type");

    let title = "Action Confirmed";
    let message = "Your request has been successfully processed.";
    let iconColor = "text-cyan-400 border-cyan-900/40 bg-cyan-950/60 shadow-[0_0_15px_rgba(34,211,238,0.15)]";
    let iconSvg = (
        <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
    );

    if (type === "logout") {
        title = "Successfully Logged Out";
        message = "You have been securely logged out of your session. Your local cryptographic vault keys have been cleared from memory.";
        iconColor = "text-cyan-400 border-cyan-900/40 bg-cyan-950/60 shadow-[0_0_15px_rgba(34,211,238,0.15)]";
        iconSvg = (
            <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 01-3-3h4a3 3 0 013 3v1" />
            </svg>
        );
    } else if (type === "delete") {
        title = "Account Permanently Deleted";
        message = "Your ZK Vault account and all associated encrypted vault credentials have been completely and permanently erased from our servers. This action is irreversible.";
        iconColor = "text-red-400 border-red-900/40 bg-red-950/60 shadow-[0_0_15px_rgba(239,68,68,0.15)]";
        iconSvg = (
            <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
        );
    }

    return (
        <div className="max-w-md w-full p-6 md:p-8 bg-zinc-900/40 border border-zinc-900 rounded-2xl text-center space-y-6 shadow-2xl backdrop-blur-md">
            <div className="flex justify-center">
                <div className={`w-16 h-16 rounded-2xl flex items-center justify-center border ${iconColor}`}>
                    {iconSvg}
                </div>
            </div>
            
            <div className="space-y-2">
                <h1 className="text-2xl font-extrabold text-white tracking-tight">{title}</h1>
                <p className="text-sm text-zinc-400 leading-relaxed">{message}</p>
            </div>

            <div className="pt-4">
                <Link
                    href="/"
                    className="inline-flex items-center justify-center w-full px-5 py-3 rounded-xl text-sm font-semibold bg-zinc-900 border border-zinc-800 text-zinc-300 hover:text-white hover:border-zinc-700 hover:bg-[#18191b] active:bg-[#111213] transition-all shadow-md hover:shadow-lg"
                >
                    Return to Login
                </Link>
            </div>
        </div>
    );
}

export default function ConfirmationPage() {
    return (
        <main className="min-h-screen flex items-center justify-center bg-zinc-950 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-zinc-900 via-zinc-950 to-black text-white px-6 font-sans">
            <Suspense fallback={<div className="text-zinc-500 text-sm font-medium">Loading details...</div>}>
                <ConfirmationContent />
            </Suspense>
        </main>
    );
}
