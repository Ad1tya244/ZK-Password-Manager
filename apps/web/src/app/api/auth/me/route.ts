import { NextRequest } from "next/server";
import { getAuthUser } from "@/lib/server-auth";
import * as authService from "@/lib/services/auth.service";

export async function GET(request: NextRequest) {
    const authUser = getAuthUser(request);
    if (!authUser) return Response.json({ error: "Access denied. No token provided." }, { status: 401 });

    try {
        const user = await authService.getUserById(authUser.userId);
        if (!user) return Response.json({ error: "User not found" }, { status: 404 });

        return Response.json({
            user: {
                id: user.id,
                username: user.username,
                hasRecovery: !!user.recoveryKeyHash,
                is2faEnabled: !!user.twoFactorSecret,
                recoveryConfiguredAt: user.recoveryConfiguredAt,
            },
        });
    } catch {
        return Response.json({ error: "Failed to fetch profile" }, { status: 500 });
    }
}
