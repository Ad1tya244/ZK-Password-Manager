import { NextRequest, NextResponse } from "next/server";
import { generateToken, generateRefreshToken } from "@zk/crypto";
import { LoginSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";
import { rateLimitResponse } from "@/lib/rate-limit";

const IS_PROD = process.env.NODE_ENV === "production";

export async function POST(request: NextRequest) {
    const ip = request.headers.get("x-forwarded-for") ?? request.headers.get("x-real-ip") ?? "unknown";
    const limited = rateLimitResponse(`login:${ip}`);
    if (limited) return limited;

    const parsed = await validateBody(request, LoginSchema);
    if (!parsed.success) return parsed.response;

    const { username, password } = parsed.data;

    try {
        const { user, require2fa } = await authService.loginUser(username, password);

        if (require2fa) {
            return NextResponse.json({
                require2fa: true,
                username,
                message: "Enter code from authenticator app",
            });
        }

        const accessToken = generateToken({ userId: user.id, username: user.username });
        const refreshToken = generateRefreshToken({ userId: user.id });

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
