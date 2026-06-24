import { NextRequest, NextResponse } from "next/server";
import { getAuthUser } from "@/lib/server-auth";
import { prisma } from "@/lib/prisma";

export async function POST(request: NextRequest) {
    const authUser = await getAuthUser(request);
    if (!authUser) {
        return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });
    }

    try {
        // Revoke all sessions belonging to the user
        await prisma.session.deleteMany({
            where: { userId: authUser.userId },
        });

        const response = NextResponse.json({ message: "Logged out from all devices" });
        response.cookies.delete("accessToken");
        response.cookies.delete("refreshToken");
        return response;
    } catch (error: unknown) {
        const message = error instanceof Error ? error.message : "Failed to logout all devices";
        return NextResponse.json({ error: message }, { status: 500 });
    }
}
