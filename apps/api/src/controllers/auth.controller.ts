import { Request, Response } from "express";
import * as authService from "../services/auth.service";

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

import { generateToken, generateRefreshToken } from "@zk/crypto";
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

        // If 2FA not enabled, login directly
        const accessToken = generateToken({ userId: user.id, username: user.username });
        const refreshToken = generateRefreshToken({ userId: user.id });

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

        const { isValid, user } = await authService.verifyTwoFactorToken(username, token, secret);

        // If enabling (secret present), save it
        if (secret) {
            await authService.enableTwoFactor(username, secret);
        }

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

        return res.json({ user });
    } catch (error: any) {
        return res.status(401).json({ error: error.message });
    }
};

export const logout = (req: Request, res: Response) => {
    res.clearCookie("refreshToken");
    res.clearCookie("accessToken");
    return res.json({ message: "Logged out" });
};

export const me = (req: Request, res: Response) => {
    // @ts-ignore - user is attached by middleware
    const user = req.user;
    return res.json({ user });
};

export const deleteAccount = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user?.userId;
        const { password } = req.body;

        if (!userId) {
            return res.status(401).json({ error: "Unauthorized" });
        }

        if (!password) {
            return res.status(400).json({ error: "Password required to delete account" });
        }

        try {
            await authService.deleteUser(userId, password);
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
