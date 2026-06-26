import { hashPassword, verifyPassword } from "@zk/crypto";
import { authenticator } from "@otplib/preset-default";
import { randomBytes, createHash } from "crypto";
import { prisma } from "@/lib/prisma";

// ─── User ──────────────────────────────────────────────────────────────────────

export const registerUser = async (username: string, password: string) => {
    const existingUser = await prisma.user.findUnique({ where: { username } });
    if (existingUser) throw new Error("Username already taken");

    const { hash, salt } = await hashPassword(password);
    const vaultSalt = randomBytes(16).toString("hex");

    const user = await prisma.user.create({
        data: { username, passwordHash: hash, salt, vaultSalt },
    });

    return { id: user.id, username: user.username };
};

export const getUserById = async (id: string) => {
    return await prisma.user.findUnique({ where: { id } });
};

// ─── Password ─────────────────────────────────────────────────────────────────

export interface LoginUserResponse {
    user: {
        id: string;
        username: string;
        encryptedVEK: string | null;
        vekIV: string | null;
        vekAuthTag: string | null;
        vaultSalt: string | null;
        hasRecovery: boolean;
        recoveryConfiguredAt: Date | null;
        is2faEnabled: boolean;
    };
    require2fa?: boolean;
}

export const loginUser = async (
    username: string,
    password: string
): Promise<LoginUserResponse> => {
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) throw new Error("vault not found, if new user, please create a new vault");

    if (user.lockoutUntil && user.lockoutUntil > new Date()) {
        const remaining = Math.ceil((user.lockoutUntil.getTime() - Date.now()) / 60000);
        throw new Error(`Account locked. Try again in ${remaining} minutes.`);
    }

    const isValid = await verifyPassword(password, user.passwordHash);
    if (!isValid) {
        const attempts = user.failedLoginAttempts + 1;
        let lockoutUntil = user.lockoutUntil;
        if (attempts >= 5) lockoutUntil = new Date(Date.now() + 10 * 60 * 1000);

        await prisma.user.update({
            where: { id: user.id },
            data: { failedLoginAttempts: attempts, lockoutUntil },
        });

        if (attempts >= 5) throw new Error("Account locked. Try again in 10 minutes.");
        throw new Error("Invalid password");
    }

    if (user.failedLoginAttempts > 0 || user.lockoutUntil) {
        await prisma.user.update({
            where: { id: user.id },
            data: { failedLoginAttempts: 0, lockoutUntil: null },
        });
    }

    return {
        user: {
            id: user.id,
            username: user.username,
            encryptedVEK: user.encryptedVEK ? user.encryptedVEK.toString("base64") : null,
            vekIV: user.vekIV ? user.vekIV.toString("base64") : null,
            vekAuthTag: user.vekAuthTag ? user.vekAuthTag.toString("base64") : null,
            vaultSalt: user.vaultSalt,
            hasRecovery: !!user.recoveryKeyHash,
            recoveryConfiguredAt: user.recoveryConfiguredAt,
            is2faEnabled: !!user.twoFactorSecret,
        },
        require2fa: !!user.twoFactorSecret,
    };
};

export const verifyUserPassword = async (userId: string, password: string) => {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new Error("User not found");
    return await verifyPassword(password, user.passwordHash);
};

export const deleteUser = async (userId: string, password?: string, totpToken?: string) => {
    if (password) {
        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) throw new Error("User not found");

        const isValid = await verifyPassword(password, user.passwordHash);
        if (!isValid) throw new Error("Invalid password");

        if (user.twoFactorSecret) {
            if (!totpToken) throw new Error("Two-Factor Authentication code required");
            const isTotpValid = authenticator.check(totpToken, user.twoFactorSecret);
            if (!isTotpValid) throw new Error("Invalid Two-Factor Authentication code");
        }
    }
    return await prisma.user.delete({ where: { id: userId } });
};

// ─── 2FA ──────────────────────────────────────────────────────────────────────

export const generateTwoFactorSecret = (username: string) => {
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(username, "ZK Password Manager", secret);
    return { secret, otpauth };
};

export const verifyTwoFactorToken = async (
    username: string,
    token: string,
    secret?: string,
    isReconfigure?: boolean
) => {
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) throw new Error("User not found");

    // Prevent overriding/bypassing existing 2FA configuration unless reconfiguring
    if (user.twoFactorSecret && secret && !isReconfigure) {
        throw new Error("2FA is already configured for this user");
    }

    const secretToVerify = secret ?? user.twoFactorSecret;
    if (!secretToVerify) throw new Error("2FA not enabled for this user");

    const isValid = authenticator.check(token, secretToVerify);
    if (!isValid) throw new Error("Invalid TOTP code");

    return { isValid, user };
};

export const enableTwoFactor = async (username: string, secret: string) => {
    await prisma.user.update({ where: { username }, data: { twoFactorSecret: secret } });
};

// ─── VEK ─────────────────────────────────────────────────────────────────────

export const saveVEK = async (
    userId: string,
    encryptedVEK: Buffer,
    iv: Buffer,
    authTag: Buffer
) => {
    return await prisma.user.update({
        where: { id: userId },
        data: { encryptedVEK, vekIV: iv, vekAuthTag: authTag },
    });
};

// ─── Recovery ─────────────────────────────────────────────────────────────────

const hashServerRecoveryKey = (clientHash: string): string => {
    return createHash("sha256").update(clientHash).digest("hex");
};

const findUserByRecoveryKeyHash = async (clientHash: string) => {
    const hashed = hashServerRecoveryKey(clientHash);
    
    // 1. Try finding by the hashed value (new design)
    let user = await prisma.user.findUnique({ where: { recoveryKeyHash: hashed } });
    if (user) return user;
    
    // 2. Fall back to unhashed value (legacy design, migration path)
    user = await prisma.user.findUnique({ where: { recoveryKeyHash: clientHash } });
    if (user) {
        // Upgrade this user's recoveryKeyHash in DB immediately to prevent future issues
        await prisma.user.update({
            where: { id: user.id },
            data: { recoveryKeyHash: hashed }
        });
        user.recoveryKeyHash = hashed;
        return user;
    }
    
    return null;
};

export const setupRecovery = async (
    userId: string,
    recoveryKeyHash: string,
    recoveryEncryptedVEK: Buffer,
    recoveryVekIV: Buffer,
    recoveryVekAuthTag: Buffer
) => {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new Error("User not found");

    const hashed = hashServerRecoveryKey(recoveryKeyHash);
    return await prisma.user.update({
        where: { id: userId },
        data: {
            recoveryKeyHash: hashed,
            recoveryEncryptedVEK,
            recoveryVekIV,
            recoveryVekAuthTag,
            recoveryConfiguredAt: new Date()
        },
    });
};

export const initRecovery = async (recoveryKeyHash: string) => {
    const user = await findUserByRecoveryKeyHash(recoveryKeyHash);
    if (!user) throw new Error("Invalid Recovery Key");

    return {
        username: user.username,
        recoveryEncryptedVEK: user.recoveryEncryptedVEK?.toString("base64"),
        recoveryVekIV: user.recoveryVekIV?.toString("base64"),
        recoveryVekAuthTag: user.recoveryVekAuthTag?.toString("base64"),
    };
};

export const recoverAccount = async (
    recoveryKeyHash: string,
    newPassword: string,
    newEncryptedVEK: Buffer,
    newVekIV: Buffer,
    newVekAuthTag: Buffer,
    newVaultSalt: string,
    twoFactorSecret: string,
    totpToken: string
) => {
    const user = await findUserByRecoveryKeyHash(recoveryKeyHash);
    if (!user) throw new Error("Invalid Recovery Key");

    // Verify TOTP token against the new secret
    const isTotpValid = authenticator.check(totpToken, twoFactorSecret);
    if (!isTotpValid) throw new Error("Invalid TOTP code");

    const { hash, salt } = await hashPassword(newPassword);

    // Revoke all sessions belonging to the user on recovery
    await prisma.session.deleteMany({
        where: { userId: user.id },
    });

    return await prisma.user.update({
        where: { id: user.id },
        data: {
            passwordHash: hash,
            salt,
            vaultSalt: newVaultSalt,
            encryptedVEK: newEncryptedVEK,
            vekIV: newVekIV,
            vekAuthTag: newVekAuthTag,
            failedLoginAttempts: 0,
            lockoutUntil: null,
            twoFactorSecret, // Set the new 2FA secret
            // Consume and clear the recovery key
            recoveryKeyHash: null,
            recoveryEncryptedVEK: null,
            recoveryVekIV: null,
            recoveryVekAuthTag: null,
            recoveryConfiguredAt: null,
        },
    });
};

export const changeUserPassword = async (
    userId: string,
    currentPassword: string,
    newPassword: string,
    encryptedVEK: Buffer,
    iv: Buffer,
    authTag: Buffer,
    newVaultSalt: string
) => {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new Error("User not found");

    const isValid = await verifyPassword(currentPassword, user.passwordHash);
    if (!isValid) throw new Error("Incorrect current password");

    const { hash, salt } = await hashPassword(newPassword);

    // Revoke all active sessions on password change
    await prisma.session.deleteMany({
        where: { userId },
    });

    return await prisma.user.update({
        where: { id: userId },
        data: {
            passwordHash: hash,
            salt,
            vaultSalt: newVaultSalt,
            encryptedVEK,
            vekIV: iv,
            vekAuthTag: authTag,
        },
    });
};
