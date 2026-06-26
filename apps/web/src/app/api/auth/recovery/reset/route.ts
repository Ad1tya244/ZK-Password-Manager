import { NextRequest, NextResponse } from "next/server";
import { ResetRecoverySchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";
import { rateLimitResponse } from "@/lib/rate-limit";
import { generateToken, generateRefreshToken } from "@zk/crypto";
import { prisma } from "@/lib/prisma";
import crypto from "crypto";
import { parseUserAgent } from "@/utils/user-agent";

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

        const response = NextResponse.json({
            message: "Account recovered successfully. Please sign in again."
        });

        response.cookies.delete("accessToken");
        response.cookies.delete("refreshToken");

        return response;
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to recover account" }, { status: 400 });
    }
}
