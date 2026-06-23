import { NextRequest, NextResponse } from "next/server";
import { RegisterSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as authService from "@/lib/services/auth.service";

export async function POST(request: NextRequest) {
    const parsed = await validateBody(request, RegisterSchema);
    if (!parsed.success) return parsed.response;

    const { username, password } = parsed.data;

    try {
        const user = await authService.registerUser(username, password);
        return NextResponse.json(user, { status: 201 });
    } catch (error: any) {
        return NextResponse.json({ error: error.message }, { status: 400 });
    }
}
