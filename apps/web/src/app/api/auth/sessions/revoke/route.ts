import { NextRequest, NextResponse } from "next/server";
import { getAuthUser } from "@/lib/server-auth";
import { prisma } from "@/lib/prisma";
import crypto from "crypto";

export async function POST(request: NextRequest) {
    const authUser = await getAuthUser(request);
    if (!authUser) {
        return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });
    }

    try {
        const { sessionId } = await request.json();
        if (!sessionId) {
            return NextResponse.json({ error: "Session ID required" }, { status: 400 });
        }

        // Fetch session to check if it belongs to the user and if it's the current one
        const session = await prisma.session.findFirst({
            where: {
                id: sessionId,
                userId: authUser.userId,
            },
        });

        if (!session) {
            return NextResponse.json({ error: "Session not found" }, { status: 404 });
        }

        const token = request.cookies.get("accessToken")?.value;
        const currentHash = token ? crypto.createHash("sha256").update(token).digest("hex") : null;
        const isCurrent = session.tokenHash === currentHash;

        await prisma.session.delete({
            where: { id: sessionId },
        });

        const response = NextResponse.json({ message: "Session revoked successfully" });

        // If user revoked their current session, clear their auth cookies to log them out
        if (isCurrent) {
            response.cookies.delete("accessToken");
            response.cookies.delete("refreshToken");
        }

        return response;
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to revoke session" }, { status: 500 });
    }
}
