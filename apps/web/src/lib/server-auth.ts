import { NextRequest } from "next/server";
import { verifyToken } from "@zk/crypto";

export interface AuthUser {
    userId: string;
    username: string;
}

/**
 * Reads the accessToken cookie from a Route Handler request and verifies it.
 * Returns the decoded user payload, or null if missing/invalid.
 */
export function getAuthUser(request: NextRequest): AuthUser | null {
    const token = request.cookies.get("accessToken")?.value;
    if (!token) return null;

    const decoded = verifyToken(token);
    if (!decoded || typeof decoded !== "object") return null;

    const { userId, username } = decoded as { userId: string; username: string };
    if (!userId) return null;

    return { userId, username };
}
