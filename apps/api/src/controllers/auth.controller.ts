import { Request, Response } from "express";
import * as authService from "../services/auth.service";
import crypto from "crypto";
import { PrismaClient } from "@zk/database";
import { parseUserAgent } from "../utils/user-agent";

const prismaDb = new PrismaClient();
const IS_PROD = process.env.NODE_ENV === "production";

// Helper to handle Buffer conversion
const toBuffer = (base64: string) => Buffer.from(base64, "base64");

export const register = async (req: Request, res: Response) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: "Username and password required" });
        }
        // Basic alphanumeric validation for username
        if (!/^[a-zA-Z0-9]+$/.test(username)) {
            return res.status(400).json({ error: "Username must contain only letters and numbers" });
        }

        const user = await authService.registerUser(username, password);
        return res.status(201).json(user);
    } catch (error: any) {
        return res.status(400).json({ error: error.message });
    }
};

import { generateToken, generateRefreshToken, verifyToken } from "@zk/crypto";
import * as QRCode from "qrcode";

export const login = async (req: Request, res: Response) => {
    try {
        const { username, password } = req.body;
        // Verify credentials
        const { user, require2fa } = await authService.loginUser(username, password);

        if (require2fa) {
            return res.json({
                require2fa: true,
                username,
                message: "Enter code from authenticator app"
            });
        }

        // Revoke any existing active session for this device
        const oldToken = req.cookies.accessToken;
        if (oldToken) {
            const oldTokenHash = crypto.createHash("sha256").update(oldToken).digest("hex");
            await prismaDb.session.deleteMany({
                where: { tokenHash: oldTokenHash },
            }).catch(() => {});
        }

        // Clean up expired sessions for this user
        await prismaDb.session.deleteMany({
            where: {
                userId: user.id,
                expiresAt: { lt: new Date() },
            },
        }).catch(() => {});

        // If 2FA not enabled, login directly
        const accessToken = generateToken({ userId: user.id, username: user.username });
        const refreshToken = generateRefreshToken({ userId: user.id });

        // Save session in database
        const tokenHash = crypto.createHash("sha256").update(accessToken).digest("hex");
        const userAgentRaw = req.headers["user-agent"];
        const deviceInfo = parseUserAgent(userAgentRaw);
        await prismaDb.session.create({
            data: {
                userId: user.id,
                tokenHash,
                expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
                deviceInfo,
            },
        });

        // Return same cookies
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? "strict" : "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? "strict" : "lax",
            maxAge: 15 * 60 * 1000,
        });

        return res.json({ user });

    } catch (error: any) {
        return res.status(401).json({ error: error.message });
    }
};

export const enable2fa = async (req: Request, res: Response) => {
    try {
        const { username } = req.body;
        const { secret, otpauth } = authService.generateTwoFactorSecret(username);

        // Generate QR Code
        const qrCodeUrl = await QRCode.toDataURL(otpauth);

        return res.json({ secret, qrCodeUrl });
    } catch (error: any) {
        return res.status(400).json({ error: error.message });
    }
};

export const verify2fa = async (req: Request, res: Response) => {
    try {
        const { username, token, secret } = req.body; // 'secret' provided only during setup

        const accessTokenCookie = req.cookies.accessToken;
        let isReconfigure = false;
        if (accessTokenCookie) {
            try {
                const decoded = verifyToken(accessTokenCookie);
                if (decoded && typeof decoded === "object") {
                    const { userId, username: sessionUsername } = decoded as { userId: string; username: string };
                    const tokenHash = crypto.createHash("sha256").update(accessTokenCookie).digest("hex");
                    const session = await prismaDb.session.findUnique({ where: { tokenHash } });
                    if (session && session.userId === userId && session.expiresAt > new Date() && sessionUsername.toLowerCase() === username.toLowerCase()) {
                        isReconfigure = true;
                    }
                }
            } catch (e) {
                // Ignore decoding or db errors
            }
        }

        const { isValid, user } = await authService.verifyTwoFactorToken(username, token, secret, isReconfigure);

        // If enabling (secret present), save it
        if (secret) {
            await authService.enableTwoFactor(username, secret);
        }

        if (isReconfigure) {
            // Revoke all active sessions for this user on 2FA reconfiguration
            await prismaDb.session.deleteMany({
                where: { userId: user.id }
            });

            res.clearCookie("refreshToken");
            res.clearCookie("accessToken");

            return res.json({ message: "Two-Factor Authentication reconfigured successfully. Please sign in again." });
        }

        // Revoke any existing active session for this device
        const oldToken = req.cookies.accessToken;
        if (oldToken) {
            const oldTokenHash = crypto.createHash("sha256").update(oldToken).digest("hex");
            await prismaDb.session.deleteMany({
                where: { tokenHash: oldTokenHash },
            }).catch(() => {});
        }

        // Clean up expired sessions for this user
        await prismaDb.session.deleteMany({
            where: {
                userId: user.id,
                expiresAt: { lt: new Date() },
            },
        }).catch(() => {});

        const accessToken = generateToken({ userId: user.id, username: user.username });
        const refreshToken = generateRefreshToken({ userId: user.id });

        // Save session in database
        const tokenHash = crypto.createHash("sha256").update(accessToken).digest("hex");
        const userAgentRaw = req.headers["user-agent"];
        const deviceInfo = parseUserAgent(userAgentRaw);
        await prismaDb.session.create({
            data: {
                userId: user.id,
                tokenHash,
                expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
                deviceInfo,
            },
        });

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? "strict" : "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? "strict" : "lax",
            maxAge: 15 * 60 * 1000,
        });

        return res.json({
            user: {
                id: user.id,
                username: user.username,
                encryptedVEK: user.encryptedVEK ? user.encryptedVEK.toString('base64') : null,
                vekIV: user.vekIV ? user.vekIV.toString('base64') : null,
                vekAuthTag: user.vekAuthTag ? user.vekAuthTag.toString('base64') : null,
                vaultSalt: user.vaultSalt,
                hasRecovery: !!user.recoveryKeyHash
            }
        });
    } catch (error: any) {
        return res.status(401).json({ error: error.message });
    }
};

export const logout = async (req: Request, res: Response) => {
    try {
        const token = req.cookies.accessToken;
        if (token) {
            const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
            await prismaDb.session.deleteMany({
                where: { tokenHash }
            }).catch(() => {});
        }
    } catch (error: any) {
        console.error("Session revocation failed during Express logout:", error);
    }
    res.clearCookie("refreshToken");
    res.clearCookie("accessToken");
    return res.json({ message: "Logged out" });
};

export const logoutAll = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user?.userId;
        if (userId) {
            await prismaDb.session.deleteMany({
                where: { userId }
            });
        }
        res.clearCookie("refreshToken");
        res.clearCookie("accessToken");
        return res.json({ message: "Logged out from all devices" });
    } catch (error: any) {
        return res.status(500).json({ error: error.message || "Failed to logout all devices" });
    }
};

export const me = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user.userId;
        const user = await authService.getUserById(userId); // Need to expose this in service
        if (!user) return res.status(404).json({ error: "User not found" });

        return res.json({
            user: {
                id: user.id,
                username: user.username,
                hasRecovery: !!user.recoveryKeyHash,
                is2faEnabled: !!user.twoFactorSecret,
                createdAt: user.createdAt
            }
        });
    } catch (e) {
        return res.status(500).json({ error: "Failed to fetch profile" });
    }
};

export const verifyPassword = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user?.userId;
        const { password } = req.body;

        if (!userId) {
            return res.status(401).json({ error: "Unauthorized" });
        }

        if (!password) {
            return res.status(400).json({ error: "Password required" });
        }

        const isValid = await authService.verifyUserPassword(userId, password);
        return res.json({ isValid });
    } catch (error: any) {
        return res.status(500).json({ error: error.message });
    }
};

export const deleteAccount = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user?.userId;
        const { password, totpToken } = req.body;

        if (!userId) {
            return res.status(401).json({ error: "Unauthorized" });
        }

        if (!password) {
            return res.status(400).json({ error: "Password required to delete account" });
        }

        try {
            await authService.deleteUser(userId, password, totpToken);
        } catch (e: any) {
            return res.status(400).json({ error: e.message || "Failed to delete account" });
        }

        res.clearCookie("refreshToken");
        res.clearCookie("accessToken");

        res.status(200).json({ message: "Account deleted successfully" });
    } catch (error) {
        res.status(500).json({ error: "Failed to delete account" });
    }
};

export const saveVEK = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user.userId;
        const { encryptedVEK, vekIV, vekAuthTag } = req.body;

        if (!encryptedVEK || !vekIV || !vekAuthTag) {
            return res.status(400).json({ error: "Missing VEK fields" });
        }

        await authService.saveVEK(
            userId,
            toBuffer(encryptedVEK),
            toBuffer(vekIV),
            toBuffer(vekAuthTag)
        );

        return res.json({ message: "VEK saved successfully" });
    } catch (error: any) {
        return res.status(500).json({ error: error.message });
    }
};

export const setupRecovery = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user.userId;
        const { recoveryKeyHash, recoveryEncryptedVEK, recoveryVekIV, recoveryVekAuthTag } = req.body;

        if (!recoveryKeyHash || !recoveryEncryptedVEK || !recoveryVekIV || !recoveryVekAuthTag) {
            return res.status(400).json({ error: "Missing recovery fields" });
        }

        await authService.setupRecovery(
            userId,
            recoveryKeyHash,
            toBuffer(recoveryEncryptedVEK),
            toBuffer(recoveryVekIV),
            toBuffer(recoveryVekAuthTag)
        );

        return res.json({ message: "Recovery setup successful" });
    } catch (error: any) {
        return res.status(500).json({ error: error.message });
    }
};

export const initRecovery = async (req: Request, res: Response) => {
    try {
        const { recoveryKeyHash } = req.body;
        if (!recoveryKeyHash) return res.status(400).json({ error: "Missing recovery key hash" });

        const data = await authService.initRecovery(recoveryKeyHash);
        return res.json(data);
    } catch (error: any) {
        return res.status(400).json({ error: error.message });
    }
};

export const recoverAccount = async (req: Request, res: Response) => {
    try {
        const {
            recoveryKeyHash,
            newPassword,
            newEncryptedVEK,
            newVekIV,
            newVekAuthTag,
            newVaultSalt
        } = req.body;

        if (!recoveryKeyHash || !newPassword || !newEncryptedVEK || !newVekIV || !newVekAuthTag || !newVaultSalt) {
            return res.status(400).json({ error: "Missing fields" });
        }

        // Pass raw password to service to be hashed
        await authService.recoverAccount(
            recoveryKeyHash,
            newPassword,
            toBuffer(newEncryptedVEK),
            toBuffer(newVekIV),
            toBuffer(newVekAuthTag),
            newVaultSalt
        );

        res.clearCookie("refreshToken");
        res.clearCookie("accessToken");

        return res.json({ message: "Account recovered successfully. Please sign in again." });
    } catch (error: any) {
        return res.status(400).json({ error: error.message });
    }
};



export const changeUsername = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user?.userId;
        const { newUsername } = req.body;
        if (!newUsername) return res.status(400).json({ error: "New username required" });
        if (!/^[a-zA-Z0-9]+$/.test(newUsername)) return res.status(400).json({ error: "Username must contain only letters and numbers" });

        const user = await authService.changeUsername(userId, newUsername);

        const accessToken = generateToken({ userId: user.id, username: user.username });
        const refreshToken = generateRefreshToken({ userId: user.id });

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? "strict" : "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? "strict" : "lax",
            maxAge: 15 * 60 * 1000,
        });

        return res.json({ message: "Username updated successfully", username: user.username });
    } catch (error: any) {
        return res.status(400).json({ error: error.message });
    }
};

export const changePassword = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user?.userId;
        const { currentPassword, newPassword, encryptedVEK, vekIV, vekAuthTag, newVaultSalt } = req.body;

        if (!currentPassword || !newPassword || !encryptedVEK || !vekIV || !vekAuthTag || !newVaultSalt) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        await authService.changeUserPassword(
            userId,
            currentPassword,
            newPassword,
            toBuffer(encryptedVEK),
            toBuffer(vekIV),
            toBuffer(vekAuthTag),
            newVaultSalt
        );

        res.clearCookie("refreshToken");
        res.clearCookie("accessToken");

        return res.json({ message: "Master password changed successfully" });
    } catch (error: any) {
        return res.status(400).json({ error: error.message });
    }
};

export const listSessions = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user?.userId;
        const token = req.cookies?.accessToken;
        const currentHash = token ? crypto.createHash("sha256").update(token).digest("hex") : null;

        const sessions = await prismaDb.session.findMany({
            where: { userId },
            orderBy: { createdAt: "desc" }
        });

        return res.json({
            sessions: sessions.map(s => ({
                id: s.id,
                createdAt: s.createdAt,
                expiresAt: s.expiresAt,
                isCurrent: s.tokenHash === currentHash,
                deviceInfo: s.deviceInfo || "Unknown Device"
            }))
        });
    } catch (error: any) {
        return res.status(500).json({ error: error.message });
    }
};

export const revokeSession = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user?.userId;
        const { sessionId } = req.body;
        if (!sessionId) return res.status(400).json({ error: "Session ID required" });

        const session = await prismaDb.session.findFirst({
            where: { id: sessionId, userId }
        });

        if (!session) return res.status(404).json({ error: "Session not found" });

        const token = req.cookies?.accessToken;
        const currentHash = token ? crypto.createHash("sha256").update(token).digest("hex") : null;
        const isCurrent = session.tokenHash === currentHash;

        await prismaDb.session.delete({
            where: { id: sessionId }
        });

        if (isCurrent) {
            res.clearCookie("refreshToken");
            res.clearCookie("accessToken");
        }

        return res.json({ message: "Session revoked successfully" });
    } catch (error: any) {
        return res.status(500).json({ error: error.message });
    }
};
