import { PrismaClient } from "@zk/database";
import { hashPassword, verifyPassword, generateToken, generateRefreshToken } from "@zk/crypto";

const prisma = new PrismaClient();

export const registerUser = async (username: string, password: string) => {
    const existingUser = await prisma.user.findUnique({ where: { username } });
    if (existingUser) {
        throw new Error("Username already taken");
    }

    const { hash, salt } = await hashPassword(password);

    const user = await prisma.user.create({
        data: {
            username,
            passwordHash: hash,
            salt: salt,
        },
    });

    return { id: user.id, username: user.username };
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

    const isValid = await verifyPassword(password, user.passwordHash);
    if (!isValid) {
        throw new Error("Invalid password");
    }

    return { user, require2fa: !!user.twoFactorSecret };
};

export const deleteUser = async (userId: string, password?: string) => {
    // If password provided, verify it first
    if (password) {
        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) throw new Error("User not found");

        const isValid = await verifyPassword(password, user.passwordHash);
        if (!isValid) throw new Error("Invalid password");
    }

    return await prisma.user.delete({
        where: { id: userId },
    });
};
