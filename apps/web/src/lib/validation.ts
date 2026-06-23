import { NextResponse } from "next/server";
import { ZodSchema } from "zod";

export async function validateBody<T>(
    request: Request,
    schema: ZodSchema<T>
): Promise<{ success: true; data: T } | { success: false; response: NextResponse }> {
    try {
        const body = await request.json();
        const parsed = schema.safeParse(body);
        if (!parsed.success) {
            return {
                success: false,
                response: NextResponse.json(
                    {
                        error: "Validation failed",
                        details: parsed.error.flatten().fieldErrors,
                    },
                    { status: 400 }
                ),
            };
        }
        return { success: true, data: parsed.data };
    } catch (e) {
        return {
            success: false,
            response: NextResponse.json(
                { error: "Invalid JSON payload" },
                { status: 400 }
            ),
        };
    }
}
