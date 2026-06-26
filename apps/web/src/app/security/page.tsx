import Link from "next/link";

export default function SecurityPage() {
    return (
        <main className="min-h-screen bg-zinc-950 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-zinc-900 via-zinc-950 to-black text-white font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
            <div className="max-w-4xl mx-auto px-6 py-12 md:py-20 space-y-12">
                
                {/* Navigation / Header */}
                <div className="flex items-center justify-between pb-6 border-b border-zinc-800/80">
                    <div className="flex items-center gap-3">
                        <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-cyan-950/60 text-cyan-400 border border-cyan-900/40 shadow-[0_0_15px_rgba(34,211,238,0.1)]">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                        </div>
                        <div>
                            <h2 className="text-sm font-bold text-white tracking-wider uppercase">ZK Vault</h2>
                            <p className="text-[10px] text-zinc-500 font-mono">Security & Cryptographic Architecture</p>
                        </div>
                    </div>
                    
                    <Link 
                        href="/" 
                        className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#111213] border border-zinc-800 text-zinc-300 hover:text-white hover:border-zinc-700 hover:bg-[#18191b] transition-all"
                    >
                        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                        </svg>
                        Back to Vault
                    </Link>
                </div>

                {/* Hero section */}
                <div className="space-y-4">
                    <h1 className="text-3xl md:text-4xl font-extrabold text-white tracking-tight leading-tight">
                        Our Security Architecture
                    </h1>
                    <p className="text-zinc-400 text-sm md:text-base leading-relaxed max-w-3xl">
                        At ZK Vault, we believe privacy is a fundamental right. We operate under a strict <strong>zero-knowledge model</strong>: your master password never leaves your browser, and your credentials are encrypted before they ever reach our servers. Your trust is protected by mathematical certainty, not just promises.
                    </p>
                </div>

                {/* Main Details */}
                <div className="space-y-10">
                    
                    {/* Section 1 */}
                    <div className="space-y-4">
                        <div className="flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                            <h3 className="text-base font-bold text-white tracking-wide">1. Local Key Derivation</h3>
                        </div>
                        <div className="p-5 bg-zinc-900/10 border border-zinc-800/80 rounded-xl space-y-3">
                            <p className="text-zinc-300 text-xs md:text-sm font-semibold">
                                Why it exists: To ensure your master password is never sent to our servers or exposed in transit.
                            </p>
                            <p className="text-zinc-400 text-xs md:text-sm leading-relaxed">
                                Instead of sending your password to authenticate, your device performs local password stretching. It derives a Key Encryption Key (KEK) to encrypt your vault locally, and a separate verification hash to prove your identity to the server.
                            </p>
                            <ul className="space-y-2 text-[11px] md:text-xs text-zinc-500 font-mono pl-4 border-l border-zinc-800">
                                <li><strong className="text-zinc-300">Method:</strong> PBKDF2-HMAC-SHA256 (100,000 iterations)</li>
                                <li><strong className="text-zinc-300">Salt:</strong> Unique, cryptographically random salt derived from your username</li>
                            </ul>
                        </div>
                    </div>

                    {/* Section 2 */}
                    <div className="space-y-4">
                        <div className="flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-teal-400"></span>
                            <h3 className="text-base font-bold text-white tracking-wide">2. Client-Side Vault Encryption</h3>
                        </div>
                        <div className="p-5 bg-zinc-900/10 border border-zinc-800/80 rounded-xl space-y-3">
                            <p className="text-zinc-300 text-xs md:text-sm font-semibold">
                                Why it exists: To protect your credentials from unauthorized access—even in the event of a total server breach.
                            </p>
                            <p className="text-zinc-400 text-xs md:text-sm leading-relaxed">
                                Every username, password, URL, and secure note is sealed locally in your browser before transport. The server only receives and stores unreadable ciphertext blocks.
                            </p>
                            <ul className="space-y-2 text-[11px] md:text-xs text-zinc-500 font-mono pl-4 border-l border-zinc-800">
                                <li><strong className="text-zinc-300">Encryption Standard:</strong> AES-GCM (256-bit key) using Web Crypto API</li>
                                <li><strong className="text-zinc-300">Integrity:</strong> Sealed with unique Initialization Vectors (IV) and a 128-bit authentication tag to prevent data tampering</li>
                            </ul>
                        </div>
                    </div>

                    {/* Section 3 */}
                    <div className="space-y-4">
                        <div className="flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                            <h3 className="text-base font-bold text-white tracking-wide">3. Server-Blind Emergency Recovery</h3>
                        </div>
                        <div className="p-5 bg-zinc-900/10 border border-zinc-800/80 rounded-xl space-y-3">
                            <p className="text-zinc-300 text-xs md:text-sm font-semibold">
                                Why it exists: To enable account recovery without backdoor access.
                            </p>
                            <p className="text-zinc-400 text-xs md:text-sm leading-relaxed">
                                Because we cannot reset your master password, we provide a secure self-custody recovery mechanism. A locally generated recovery key wraps your vault key. The server only stores a hash of the recovery identifier to validate your recovery request.
                            </p>
                            <ul className="space-y-2 text-[11px] md:text-xs text-zinc-500 font-mono pl-4 border-l border-zinc-800">
                                <li><strong className="text-zinc-300">Key Derivation:</strong> HKDF-SHA256 from a 256-bit high-entropy random recovery phrase</li>
                                <li><strong className="text-zinc-300">Verification Hash:</strong> Hashed via SHA-256 for server authentication</li>
                            </ul>
                        </div>
                    </div>

                    {/* Section 4 */}
                    <div className="space-y-4">
                        <div className="flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-fuchsia-400"></span>
                            <h3 className="text-base font-bold text-white tracking-wide">4. Server Infrastructure & Multi-Factor Security</h3>
                        </div>
                        <div className="p-5 bg-zinc-900/10 border border-zinc-800/80 rounded-xl space-y-3">
                            <p className="text-zinc-300 text-xs md:text-sm font-semibold">
                                Why it exists: To defend your account against brute-force attacks and session hijacking.
                            </p>
                            <p className="text-zinc-400 text-xs md:text-sm leading-relaxed">
                                Even though our server cannot read your credentials, we use modern authentication hashing to protect login requests. Active sessions are secured using isolated server session states and secure cookies.
                            </p>
                            <ul className="space-y-2 text-[11px] md:text-xs text-zinc-500 font-mono pl-4 border-l border-zinc-800">
                                <li><strong className="text-zinc-300">Server Hashing:</strong> Argon2id (memory-hard, GPU-resistant hashing)</li>
                                <li><strong className="text-zinc-300">Session Protection:</strong> HttpOnly, secure, SameSite cookies with SHA-256 hashed identifiers</li>
                                <li><strong className="text-zinc-300">Multi-Factor Safety:</strong> Mandatory Time-Based One-Time Passwords (TOTP)</li>
                            </ul>
                        </div>
                    </div>

                </div>

                {/* Bottom Callout */}
                <div className="p-5 bg-cyan-950/20 border border-cyan-900/30 rounded-xl text-center space-y-3">
                    <p className="text-xs md:text-sm text-zinc-300 font-medium">
                        ZK Vault is built entirely on open, industry-standard cryptography. By employing a true zero-knowledge architecture, we ensure your digital life is protected by mathematical certainty—not just promises.
                    </p>
                    <Link 
                        href="/" 
                        className="inline-block text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors underline underline-offset-4"
                    >
                        Return to sign in page
                    </Link>
                </div>

            </div>
        </main>
    );
}
