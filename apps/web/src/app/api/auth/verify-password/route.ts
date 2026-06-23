import { NextRequest, NextResponse } from "next/server";
import { getAuthUser } from "@/lib/server-auth";
import { VerifyPasswordSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";

export async function POST(request: NextRequest) {
    const authUser = getAuthUser(request);
    if (!authUser) return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });

    const parsed = await validateBody(request, VerifyPasswordSchema);
    if (!parsed.success) return parsed.response;

    const { password } = parsed.data;

    try {
        const isValid = await authService.verifyUserPassword(authUser.userId, password);
        return NextResponse.json({ isValid });
    } catch (error: any) {
        return NextResponse.json({ error: error.message }, { status: 500 });
    }
}
