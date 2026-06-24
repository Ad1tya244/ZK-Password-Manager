import { NextRequest, NextResponse } from "next/server";
import { getAuthUser } from "@/lib/server-auth";
import { UpdateVaultItemSchema } from "@zk/shared";
import { validateBody } from "@/lib/validation";
import * as vaultService from "@/lib/services/vault.service";
import { z } from "zod";

const toBuffer = (base64: string) => Buffer.from(base64, "base64");
const toBase64 = (buffer: Buffer) => buffer.toString("base64");

interface RouteParams {
    params: {
        id: string;
    };
}

const IdSchema = z.string().uuid("Invalid item ID format");

export async function GET(request: NextRequest, { params }: RouteParams) {
    const authUser = await getAuthUser(request);
    if (!authUser) return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });

    const parsedId = IdSchema.safeParse(params.id);
    if (!parsedId.success) {
        return NextResponse.json({ error: parsedId.error.errors[0].message }, { status: 400 });
    }
    const id = parsedId.data;

    try {
        const item = await vaultService.getVaultItem(authUser.userId, id);

        if (!item) return NextResponse.json({ error: "Item not found" }, { status: 404 });

        return NextResponse.json({
            ...item,
            encryptedBlob: toBase64(item.encryptedBlob as Buffer),
            iv: toBase64(item.iv as Buffer),
            authTag: toBase64(item.authTag as Buffer),
        });
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to fetch vault item" }, { status: 500 });
    }
}

export async function PUT(request: NextRequest, { params }: RouteParams) {
    const authUser = await getAuthUser(request);
    if (!authUser) return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });

    const parsedId = IdSchema.safeParse(params.id);
    if (!parsedId.success) {
        return NextResponse.json({ error: parsedId.error.errors[0].message }, { status: 400 });
    }
    const id = parsedId.data;

    const parsedBody = await validateBody(request, UpdateVaultItemSchema);
    if (!parsedBody.success) return parsedBody.response;

    const { encryptedBlob, iv, authTag } = parsedBody.data;

    try {
        const item = await vaultService.updateVaultItem(
            authUser.userId,
            id,
            toBuffer(encryptedBlob),
            toBuffer(iv),
            toBuffer(authTag)
        );

        return NextResponse.json({
            ...item,
            encryptedBlob: toBase64(item.encryptedBlob as Buffer),
            iv: toBase64(item.iv as Buffer),
            authTag: toBase64(item.authTag as Buffer),
        });
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to update vault item" }, { status: 500 });
    }
}

export async function DELETE(request: NextRequest, { params }: RouteParams) {
    const authUser = await getAuthUser(request);
    if (!authUser) return NextResponse.json({ error: "Access denied. No token provided." }, { status: 401 });

    const parsedId = IdSchema.safeParse(params.id);
    if (!parsedId.success) {
        return NextResponse.json({ error: parsedId.error.errors[0].message }, { status: 400 });
    }
    const id = parsedId.data;

    try {
        await vaultService.deleteVaultItem(authUser.userId, id);
        return NextResponse.json({ message: "Item deleted" });
    } catch (error: any) {
        return NextResponse.json({ error: error.message || "Failed to delete vault item" }, { status: 500 });
    }
}
