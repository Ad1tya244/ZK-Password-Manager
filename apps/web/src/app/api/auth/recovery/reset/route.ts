import { NextRequest, NextResponse } from "next/server";
import { ResetRecoverySchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";
import { rateLimitResponse } from "@/lib/rate-limit";
import { generateToken, generateRefreshToken } from "@zk/crypto";
import { prisma } from "@/lib/prisma";
import crypto from "crypto";

const toBuffer = (base64: string) => Buffer.from(base64, "base64");
const IS_PROD = process.env.NODE_ENV === "production";

export async function POST(request: NextRequest) {
    const ip = request.headers.get("x-forwarded-for") ?? request.headers.get("x-real-ip") ?? "unknown";
    const limited = await rateLimitResponse(`recovery-reset:${ip}`);
    if (limited) return limited;

    const parsed = await validateBody(request, ResetRecoverySchema);
    if (!parsed.success) return parsed.response;

    const {
        recoveryKeyHash,
        newPassword,
        newEncryptedVEK,
        newVekIV,
        newVekAuthTag,
        newVaultSalt,
        twoFactorSecret,
        totpToken
    } = parsed.data;

    try {
        const user = await authService.recoverAccount(
            recoveryKeyHash,
            newPassword,
            toBuffer(newEncryptedVEK),
            toBuffer(newVekIV),
            toBuffer(newVekAuthTag),
            newVaultSalt,
            twoFactorSecret,
            totpToken
        );

        // Immediately generate access and refresh tokens to log the user in
        const accessToken = generateToken({ userId: user.id, username: user.username });
        const refreshToken = generateRefreshToken({ userId: user.id });

        // Save session in database
        const tokenHash = crypto.createHash("sha256").update(accessToken).digest("hex");
        await prisma.session.create({
            data: {
                userId: user.id,
                tokenHash,
                expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
            },
        });

        const response = NextResponse.json({
            message: "Account recovered and logged in successfully",
            user: {
                id: user.id,
                username: user.username,
                encryptedVEK: user.encryptedVEK ? user.encryptedVEK.toString("base64") : null,
                vekIV: user.vekIV ? user.vekIV.toString("base64") : null,
                vekAuthTag: user.vekAuthTag ? user.vekAuthTag.toString("base64") : null,
                vaultSalt: user.vaultSalt,
                hasRecovery: !!user.recoveryKeyHash,
                recoveryConfiguredAt: user.recoveryConfiguredAt,
            }
        });

        response.cookies.set("accessToken", accessToken, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? "strict" : "lax",
            maxAge: 15 * 60,
            path: "/",
        });
        response.cookies.set("refreshToken", refreshToken, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? "strict" : "lax",
            maxAge: 7 * 24 * 60 * 60,
            path: "/",
        });

        return response;
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to recover account" }, { status: 400 });
    }
}
