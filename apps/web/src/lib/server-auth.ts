import { NextRequest } from "next/server";
import { verifyToken } from "@zk/crypto";
import { prisma } from "@/lib/prisma";
import crypto from "crypto";

export interface AuthUser {
    userId: string;
    username: string;
}

/**
 * Reads the accessToken cookie from a Route Handler request and verifies both the JWT
 * and the existence of the session in the database.
 * Returns the decoded user payload, or null if missing/invalid.
 */
export async function getAuthUser(request: NextRequest): Promise<AuthUser | null> {
    const token = request.cookies.get("accessToken")?.value;
    if (!token) return null;

    const decoded = verifyToken(token);
    if (!decoded || typeof decoded !== "object") return null;

    const { userId, username } = decoded as { userId: string; username: string };
    if (!userId) return null;

    // Compute the SHA-256 hash of the session/JWT token
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    // Fetch the session from the database
    const session = await prisma.session.findUnique({
        where: { tokenHash },
    });

    // Check if the session exists, belongs to the correct user, and has not expired
    if (!session || session.userId !== userId || session.expiresAt < new Date()) {
        return null;
    }

    return { userId, username };
}
