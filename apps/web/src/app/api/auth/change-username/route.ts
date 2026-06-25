import { NextRequest, NextResponse } from "next/server";
import { getAuthUser } from "@/lib/server-auth";
import { ChangeUsernameSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import { prisma } from "@/lib/prisma";
import { generateToken, generateRefreshToken } from "@zk/crypto";
import crypto from "crypto";
import { parseUserAgent } from "@/utils/user-agent";

const IS_PROD = process.env.NODE_ENV === "production";

export async function POST(request: NextRequest) {
    const authUser = await getAuthUser(request);
    if (!authUser) {
        return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });
    }

    const parsed = await validateBody(request, ChangeUsernameSchema);
    if (!parsed.success) return parsed.response;

    const { newUsername } = parsed.data;

    try {
        // Check if username is already taken
        const existing = await prisma.user.findUnique({
            where: { username: newUsername },
        });
        if (existing) {
            return NextResponse.json({ error: "Username already taken" }, { status: 400 });
        }

        // Update username
        const user = await prisma.user.update({
            where: { id: authUser.userId },
            data: { username: newUsername },
        });

        // Revoke the current session
        const currentToken = request.cookies.get("accessToken")?.value;
        if (currentToken) {
            const currentHash = crypto.createHash("sha256").update(currentToken).digest("hex");
            await prisma.session.deleteMany({
                where: { tokenHash: currentHash },
            });
        }

        // Generate new session tokens
        const accessToken = generateToken({ userId: user.id, username: user.username });
        const refreshToken = generateRefreshToken({ userId: user.id });

        // Save new session
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

        const response = NextResponse.json({
            message: "Username updated successfully",
            username: user.username,
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
        return NextResponse.json({ error: error.message || "Failed to change username" }, { status: 500 });
    }
}
