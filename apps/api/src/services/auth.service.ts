import { PrismaClient } from "@zk/database";
import { hashPassword, verifyPassword, generateToken, generateRefreshToken } from "@zk/crypto";

const prisma = new PrismaClient();

import { randomBytes } from "crypto";

export const registerUser = async (username: string, password: string) => {
    const existingUser = await prisma.user.findUnique({ where: { username } });
    if (existingUser) {
        throw new Error("Username already taken");
    }

    const { hash, salt } = await hashPassword(password);
    const vaultSalt = randomBytes(16).toString("hex");

    const user = await prisma.user.create({
        data: {
            username,
            passwordHash: hash,
            salt: salt,
            vaultSalt: vaultSalt,
        },
    });

    return { id: user.id, username: user.username };
};

export const getUserById = async (id: string) => {
    return await prisma.user.findUnique({ where: { id } });
};



import { authenticator } from "@otplib/preset-default";

export const generateTwoFactorSecret = (username: string) => {
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(username, "ZK Password Manager", secret);
    return { secret, otpauth };
};

export const verifyTwoFactorToken = async (username: string, token: string, secret?: string) => {
    // If secret provided (setup phase), use it. Otherwise fetch from DB (login phase).
    let secretToVerify = secret;

    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) throw new Error("User not found");

    if (!secretToVerify) {
        if (!user.twoFactorSecret) throw new Error("2FA not enabled for this user");
        secretToVerify = user.twoFactorSecret;
    }

    const isValid = authenticator.check(token, secretToVerify);
    if (!isValid) throw new Error("Invalid TOTP code");

    // If verifying for setup (passed secret explicitly), check consistency and don't save yet? 
    // Actually, usually we verify then save. The controller should handle saving.
    return { isValid, user };
};

export const enableTwoFactor = async (username: string, secret: string) => {
    await prisma.user.update({
        where: { username },
        data: { twoFactorSecret: secret }
    });
};

export const loginUser = async (username: string, password: string): Promise<{ user: any, require2fa?: boolean }> => {
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) {
        throw new Error("vault not found, if new user, please create a new vault");
    }

    // Check for Lockout
    if (user.lockoutUntil && user.lockoutUntil > new Date()) {
        const remaining = Math.ceil((user.lockoutUntil.getTime() - Date.now()) / 60000);
        throw new Error(`Account locked. Try again in ${remaining} minutes.`);
    }

    const isValid = await verifyPassword(password, user.passwordHash);
    if (!isValid) {
        // Increment failed attempts
        const attempts = user.failedLoginAttempts + 1;
        let lockoutUntil = user.lockoutUntil;

        if (attempts >= 5) {
            lockoutUntil = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
        }

        await prisma.user.update({
            where: { id: user.id },
            data: {
                failedLoginAttempts: attempts,
                lockoutUntil: lockoutUntil
            }
        });

        if (attempts >= 5) {
            throw new Error(`Account locked. Try again in 10 minutes.`);
        }

        throw new Error("Invalid password");
    }

    // Reset on success
    if (user.failedLoginAttempts > 0 || user.lockoutUntil) {
        await prisma.user.update({
            where: { id: user.id },
            data: { failedLoginAttempts: 0, lockoutUntil: null }
        });
    }

    return {
        user: {
            id: user.id,
            username: user.username,
            encryptedVEK: user.encryptedVEK ? user.encryptedVEK.toString('base64') : null,
            vekIV: user.vekIV ? user.vekIV.toString('base64') : null,
            vekAuthTag: user.vekAuthTag ? user.vekAuthTag.toString('base64') : null,
            vaultSalt: user.vaultSalt,
            hasRecovery: !!user.recoveryKeyHash
        },
        require2fa: !!user.twoFactorSecret
    };
};

export const verifyUserPassword = async (userId: string, password: string) => {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new Error("User not found");

    const isValid = await verifyPassword(password, user.passwordHash);
    return isValid;
};

export const deleteUser = async (userId: string, password?: string, totpToken?: string) => {
    // If password provided, verify it first
    if (password) {
        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) throw new Error("User not found");

        const isValid = await verifyPassword(password, user.passwordHash);
        if (!isValid) throw new Error("Invalid password");

        // Enforce 2FA if enabled
        if (user.twoFactorSecret) {
            if (!totpToken) {
                throw new Error("Two-Factor Authentication code required");
            }
            const isTotpValid = authenticator.check(totpToken, user.twoFactorSecret);
            if (!isTotpValid) {
                throw new Error("Invalid Two-Factor Authentication code");
            }
        }
    }

    return await prisma.user.delete({
        where: { id: userId },
    });
};

export const saveVEK = async (userId: string, encryptedVEK: Buffer, iv: Buffer, authTag: Buffer) => {
    return await prisma.user.update({
        where: { id: userId },
        data: {
            encryptedVEK,
            vekIV: iv,
            vekAuthTag: authTag
        }
    });
};

export const setupRecovery = async (
    userId: string,
    recoveryKeyHash: string,
    recoveryEncryptedVEK: Buffer,
    recoveryVekIV: Buffer,
    recoveryVekAuthTag: Buffer
) => {
    return await prisma.user.update({
        where: { id: userId },
        data: {
            recoveryKeyHash,
            recoveryEncryptedVEK,
            recoveryVekIV,
            recoveryVekAuthTag
        }
    });
};

export const initRecovery = async (recoveryKeyHash: string) => {
    const user = await prisma.user.findUnique({
        where: { recoveryKeyHash }
    });

    if (!user) {
        // Return null or throw generic error to prevent enumeration?
        // For this task, throwing specific error is helpful.
        throw new Error("Invalid Recovery Key");
    }

    return {
        username: user.username,
        recoveryEncryptedVEK: user.recoveryEncryptedVEK?.toString("base64"),
        recoveryVekIV: user.recoveryVekIV?.toString("base64"),
        recoveryVekAuthTag: user.recoveryVekAuthTag?.toString("base64")
    };
};

export const recoverAccount = async (
    recoveryKeyHash: string,
    newPassword: string,
    newEncryptedVEK: Buffer,
    newVekIV: Buffer,
    newVekAuthTag: Buffer,
    newVaultSalt: string
) => {
    const user = await prisma.user.findUnique({
        where: { recoveryKeyHash }
    });

    if (!user) throw new Error("Invalid Recovery Key");

    const { hash, salt } = await hashPassword(newPassword);

    // Update password and re-wrapped VEK
    // Also reset lockout counters AND update vaultSalt
    return await prisma.user.update({
        where: { id: user.id },
        data: {
            passwordHash: hash,
            salt: salt,
            vaultSalt: newVaultSalt, // Update the explicit salt
            encryptedVEK: newEncryptedVEK,
            vekIV: newVekIV,
            vekAuthTag: newVekAuthTag,
            failedLoginAttempts: 0,
            lockoutUntil: null
        }
    });
};
