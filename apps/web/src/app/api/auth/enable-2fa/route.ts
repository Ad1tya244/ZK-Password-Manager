import { NextRequest, NextResponse } from "next/server";
import * as QRCode from "qrcode";
import { Enable2faSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";

export async function POST(request: NextRequest) {
    const parsed = await validateBody(request, Enable2faSchema);
    if (!parsed.success) return parsed.response;

    const { username } = parsed.data;

    try {
        const { secret, otpauth } = authService.generateTwoFactorSecret(username);
        const qrCodeUrl = await QRCode.toDataURL(otpauth);
        return NextResponse.json({ secret, qrCodeUrl });
    } catch (error: any) {
        return NextResponse.json({ error: error.message }, { status: 400 });
    }
}
