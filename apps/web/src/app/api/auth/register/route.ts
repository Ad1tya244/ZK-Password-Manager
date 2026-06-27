import { NextRequest, NextResponse } from "next/server";
import { RegisterSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";

export async function POST(request: NextRequest) {
    const parsed = await validateBody(request, RegisterSchema);
    if (!parsed.success) return parsed.response;

    const { username } = parsed.data;

    try {
        const result = await authService.checkUsernameAvailability(username);
        return NextResponse.json(result, { status: 200 });
    } catch (error: any) {
        return NextResponse.json({ error: error.message }, { status: 400 });
    }
}
