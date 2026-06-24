import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";
import { prisma } from "@/lib/prisma";

export async function POST(request: NextRequest) {
    const token = request.cookies.get("accessToken")?.value;
    if (token) {
        const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
        try {
            await prisma.session.deleteMany({
                where: { tokenHash },
            });
        } catch (error: unknown) {
            console.error("Session revocation failed during logout:", error);
        }
    }

    const response = NextResponse.json({ message: "Logged out" });
    response.cookies.delete("accessToken");
    response.cookies.delete("refreshToken");
    return response;
}
