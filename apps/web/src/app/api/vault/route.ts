import { NextRequest, NextResponse } from "next/server";
import { getAuthUser } from "@/lib/server-auth";
import { CreateVaultItemSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as vaultService from "@/lib/services/vault.service";

const toBuffer = (base64: string) => Buffer.from(base64, "base64");
const toBase64 = (buffer: Buffer) => buffer.toString("base64");

export async function GET(request: NextRequest) {
    const authUser = await getAuthUser(request);
    if (!authUser) return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });

    try {
        const items = await vaultService.getVaultItems(authUser.userId);

        const formatted = items.map((item) => ({
            ...item,
            encryptedBlob: toBase64(item.encryptedBlob as Buffer),
            iv: toBase64(item.iv as Buffer),
            authTag: toBase64(item.authTag as Buffer),
        }));

        return NextResponse.json(formatted);
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to list vault items" }, { status: 500 });
    }
}

export async function POST(request: NextRequest) {
    const authUser = await getAuthUser(request);
    if (!authUser) return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });

    const parsed = await validateBody(request, CreateVaultItemSchema);
    if (!parsed.success) return parsed.response;

    const { encryptedBlob, iv, authTag } = parsed.data;

    try {
        const item = await vaultService.createVaultItem(
            authUser.userId,
            toBuffer(encryptedBlob),
            toBuffer(iv),
            toBuffer(authTag)
        );

        return NextResponse.json({
            ...item,
            encryptedBlob: toBase64(item.encryptedBlob as Buffer),
            iv: toBase64(item.iv as Buffer),
            authTag: toBase64(item.authTag as Buffer),
        }, { status: 201 });
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to create vault item" }, { status: 500 });
    }
}
