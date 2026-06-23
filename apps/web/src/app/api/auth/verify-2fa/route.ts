import { NextRequest, NextResponse } from "next/server";
import { generateToken, generateRefreshToken } from "@zk/crypto";
import { Verify2faSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";
import { rateLimitResponse } from "@/lib/rate-limit";

const IS_PROD = process.env.NODE_ENV === "production";

export async function POST(request: NextRequest) {
    const ip = request.headers.get("x-forwarded-for") ?? request.headers.get("x-real-ip") ?? "unknown";
    const limited = rateLimitResponse(`verify2fa:${ip}`);
    if (limited) return limited;

    const parsed = await validateBody(request, Verify2faSchema);
    if (!parsed.success) return parsed.response;

    const { username, token, secret } = parsed.data;

    try {
        const { user } = await authService.verifyTwoFactorToken(username, token, secret);

        // If enabling 2FA (secret provided), save it
        if (secret) {
            await authService.enableTwoFactor(username, secret);
        }

        const accessToken = generateToken({ userId: user.id, username: user.username });
        const refreshToken = generateRefreshToken({ userId: user.id });

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
