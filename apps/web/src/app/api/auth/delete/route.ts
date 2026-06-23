import { NextRequest, NextResponse } from "next/server";
import { getAuthUser } from "@/lib/server-auth";
import { DeleteAccountSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";

export async function DELETE(request: NextRequest) {
    const authUser = getAuthUser(request);
    if (!authUser) return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });

    const parsed = await validateBody(request, DeleteAccountSchema);
    if (!parsed.success) return parsed.response;

    const { password, totpToken } = parsed.data;

    try {
        try {
            await authService.deleteUser(authUser.userId, password, totpToken || undefined);
        } catch (e: any) {
            return NextResponse.json({ error: e.message || "Failed to delete account" }, { status: 400 });
        }

        const response = NextResponse.json({ message: "Account deleted successfully" });
        response.cookies.delete("accessToken");
        response.cookies.delete("refreshToken");
        return response;
    } catch {
        return NextResponse.json({ error: "Failed to delete account" }, { status: 500 });
    }
}
