import { NextRequest, NextResponse } from "next/server";
import { InitRecoverySchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";
import { rateLimitResponse } from "@/lib/rate-limit";

export async function POST(request: NextRequest) {
    const ip = request.headers.get("x-forwarded-for") ?? request.headers.get("x-real-ip") ?? "unknown";
    const limited = await rateLimitResponse(`recovery-init:${ip}`);
    if (limited) return limited;

    const parsed = await validateBody(request, InitRecoverySchema);
    if (!parsed.success) return parsed.response;

    const { recoveryKeyHash } = parsed.data;

    try {
        const data = await authService.initRecovery(recoveryKeyHash);
        return NextResponse.json(data);
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to initialize recovery" }, { status: 400 });
    }
}
