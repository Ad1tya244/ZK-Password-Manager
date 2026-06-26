import { NextRequest, NextResponse } from "next/server";
import { generateToken, generateRefreshToken } from "@zk/crypto";
import { Verify2faSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";
import { rateLimitResponse } from "@/lib/rate-limit";
import { prisma } from "@/lib/prisma";
import crypto from "crypto";
import { parseUserAgent } from "@/utils/user-agent";
import { getAuthUser } from "@/lib/server-auth";

const IS_PROD = process.env.NODE_ENV === "production";

export async function POST(request: NextRequest) {
    const ip = request.headers.get("x-forwarded-for") ?? request.headers.get("x-real-ip") ?? "unknown";
    const limited = await rateLimitResponse(`verify2fa:${ip}`);
    if (limited) return limited;

    const parsed = await validateBody(request, Verify2faSchema);
    if (!parsed.success) return parsed.response;

    const { username, token, secret } = parsed.data;

    try {
        const authUser = await getAuthUser(request);
        const isReconfigure = !!(secret && authUser && authUser.username.toLowerCase() === username.toLowerCase());

        const { user } = await authService.verifyTwoFactorToken(username, token, secret, isReconfigure);

        // If enabling 2FA (secret provided), save it
        if (secret) {
            await authService.enableTwoFactor(username, secret);
        }

        if (isReconfigure) {
            // Revoke all active sessions for this user on 2FA reconfiguration
            await prisma.session.deleteMany({
                where: { userId: user.id }
            });

            const response = NextResponse.json({
                message: "Two-Factor Authentication reconfigured successfully. Please sign in again."
            });

            response.cookies.delete("accessToken");
            response.cookies.delete("refreshToken");

            return response;
        }

        // Revoke any existing active session for this device
        const oldToken = request.cookies.get("accessToken")?.value;
        if (oldToken) {
            const oldTokenHash = crypto.createHash("sha256").update(oldToken).digest("hex");
            await prisma.session.deleteMany({
                where: { tokenHash: oldTokenHash },
            }).catch(() => {});
        }

        // Clean up expired sessions for this user
        await prisma.session.deleteMany({
            where: {
                userId: user.id,
                expiresAt: { lt: new Date() },
            },
        }).catch(() => {});

        const accessToken = generateToken({ userId: user.id, username: user.username });
        const refreshToken = generateRefreshToken({ userId: user.id });

        // Persist session to database
        const tokenHash = crypto.createHash("sha256").update(accessToken).digest("hex");
        const userAgentRaw = request.headers.get("user-agent");
        const deviceInfo = parseUserAgent(userAgentRaw);
        await prisma.session.create({
            data: {
                userId: user.id,
                tokenHash,
                expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
                deviceInfo,
            },
        });

        const res = NextResponse.json({
            user: {
                id: user.id,
                username: user.username,
                encryptedVEK: user.encryptedVEK ? user.encryptedVEK.toString("base64") : null,
                vekIV: user.vekIV ? user.vekIV.toString("base64") : null,
                vekAuthTag: user.vekAuthTag ? user.vekAuthTag.toString("base64") : null,
                vaultSalt: user.vaultSalt,
                hasRecovery: !!user.recoveryKeyHash,
                recoveryConfiguredAt: user.recoveryConfiguredAt,
            },
        });

        res.cookies.set("accessToken", accessToken, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? "strict" : "lax",
            maxAge: 15 * 60,
            path: "/",
        });
        res.cookies.set("refreshToken", refreshToken, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: IS_PROD ? "strict" : "lax",
            maxAge: 7 * 24 * 60 * 60,
            path: "/",
        });

        return res;
    } catch (error: any) {
        return NextResponse.json({ error: error.message }, { status: 401 });
    }
}
