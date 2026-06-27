import { NextRequest, NextResponse } from "next/server";
import { getAuthUser } from "@/lib/server-auth";
import { prisma } from "@/lib/prisma";
import crypto from "crypto";

export async function GET(request: NextRequest) {
    const authUser = await getAuthUser(request);
    if (!authUser) {
        return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });
    }

    try {
        const token = request.cookies.get("accessToken")?.value;
        const currentHash = token ? crypto.createHash("sha256").update(token).digest("hex") : null;

        const sessions = await prisma.session.findMany({
            where: { userId: authUser.userId },
            orderBy: { createdAt: "desc" },
        });

        return NextResponse.json({
            sessions: sessions.map((s: any) => ({
                id: s.id,
                createdAt: s.createdAt,
                expiresAt: s.expiresAt,
                isCurrent: s.tokenHash === currentHash,
                deviceInfo: s.deviceInfo || "Unknown Device",
            })),
        });
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to fetch sessions" }, { status: 500 });
    }
}
