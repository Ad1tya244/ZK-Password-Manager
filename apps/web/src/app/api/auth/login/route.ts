import { NextRequest, NextResponse } from "next/server";
import { generateToken, generateRefreshToken } from "@zk/crypto";
import { LoginSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";
import { rateLimitResponse } from "@/lib/rate-limit";
import { prisma } from "@/lib/prisma";
import crypto from "crypto";

const IS_PROD = process.env.NODE_ENV === "production";

export async function POST(request: NextRequest) {
    const ip = request.headers.get("x-forwarded-for") ?? request.headers.get("x-real-ip") ?? "unknown";
    const limited = await rateLimitResponse(`login:${ip}`);
    if (limited) return limited;

    const parsed = await validateBody(request, LoginSchema);
    if (!parsed.success) return parsed.response;

    const { username, password } = parsed.data;

    try {
        const { user, require2fa } = await authService.loginUser(username, password);

        // Force 2FA setup if 2FA is not configured (e.g. after recovery)
        if (!user.is2faEnabled) {
            return NextResponse.json({
                require2faSetup: true,
                username,
                message: "Two-Factor Authentication is required. Please configure 2FA to complete login.",
            });
        }

        if (require2fa) {
            return NextResponse.json({
                require2fa: true,
                username,
                message: "Enter code from authenticator app",
            });
        }

        const accessToken = generateToken({ userId: user.id, username: user.username });
        const refreshToken = generateRefreshToken({ userId: user.id });

        // Persist session to database
        const tokenHash = crypto.createHash("sha256").update(accessToken).digest("hex");
        await prisma.session.create({
            data: {
                userId: user.id,
                tokenHash,
                expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
            },
        });

        const response = NextResponse.json({ user });
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
        return NextResponse.json({ error: error.message }, { status: 401 });
    }
}
