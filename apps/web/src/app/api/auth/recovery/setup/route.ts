import { NextRequest, NextResponse } from "next/server";
import { getAuthUser } from "@/lib/server-auth";
import { SetupRecoverySchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";

const toBuffer = (base64: string) => Buffer.from(base64, "base64");

export async function POST(request: NextRequest) {
    const authUser = getAuthUser(request);
    if (!authUser) return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });

    const parsed = await validateBody(request, SetupRecoverySchema);
    if (!parsed.success) return parsed.response;

    const { recoveryKeyHash, recoveryEncryptedVEK, recoveryVekIV, recoveryVekAuthTag } = parsed.data;

    try {
        await authService.setupRecovery(
            authUser.userId,
            recoveryKeyHash,
            toBuffer(recoveryEncryptedVEK),
            toBuffer(recoveryVekIV),
            toBuffer(recoveryVekAuthTag)
        );

        return NextResponse.json({ message: "Recovery setup successful" });
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to setup recovery" }, { status: 500 });
    }
}
