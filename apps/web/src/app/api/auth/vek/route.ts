import { NextRequest, NextResponse } from "next/server";
import { getAuthUser } from "@/lib/server-auth";
import { SaveVekSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";

const toBuffer = (base64: string) => Buffer.from(base64, "base64");

export async function POST(request: NextRequest) {
    const authUser = await getAuthUser(request);
    if (!authUser) return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });

    const parsed = await validateBody(request, SaveVekSchema);
    if (!parsed.success) return parsed.response;

    const { encryptedVEK, vekIV, vekAuthTag } = parsed.data;

    try {
        await authService.saveVEK(
            authUser.userId,
            toBuffer(encryptedVEK),
            toBuffer(vekIV),
            toBuffer(vekAuthTag)
        );

        return NextResponse.json({ message: "VEK saved successfully" });
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to save VEK" }, { status: 500 });
    }
}
