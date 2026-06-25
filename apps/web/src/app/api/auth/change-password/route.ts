import { NextRequest, NextResponse } from "next/server";
import { getAuthUser } from "@/lib/server-auth";
import { ChangePasswordSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";

const toBuffer = (base64: string) => Buffer.from(base64, "base64");

export async function POST(request: NextRequest) {
    const authUser = await getAuthUser(request);
    if (!authUser) {
        return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });
    }

    const parsed = await validateBody(request, ChangePasswordSchema);
    if (!parsed.success) return parsed.response;

    const { currentPassword, newPassword, encryptedVEK, vekIV, vekAuthTag, newVaultSalt } = parsed.data;

    try {
        await authService.changeUserPassword(
            authUser.userId,
            currentPassword,
            newPassword,
            toBuffer(encryptedVEK),
            toBuffer(vekIV),
            toBuffer(vekAuthTag),
            newVaultSalt
        );

        const response = NextResponse.json({ message: "Master password changed successfully" });
        response.cookies.delete("accessToken");
        response.cookies.delete("refreshToken");
        return response;
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to change master password" }, { status: 400 });
    }
}
