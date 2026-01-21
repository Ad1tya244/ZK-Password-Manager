import { Request, Response } from "express";
import * as vaultService from "../services/vault.service";

// Helper to handle Buffer conversion
const toBuffer = (base64: string) => Buffer.from(base64, "base64");
const toBase64 = (buffer: Buffer) => buffer.toString("base64");

export const createItem = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user.userId;
        const { encryptedBlob, iv, authTag } = req.body;

        if (!encryptedBlob || !iv || !authTag) {
            return res.status(400).json({ error: "Missing encrypted data fields" });
        }

        const item = await vaultService.createVaultItem(
            userId,
            toBuffer(encryptedBlob),
            toBuffer(iv),
            toBuffer(authTag)
        );

        return res.status(201).json({
            ...item,
            encryptedBlob: toBase64(item.encryptedBlob as Buffer),
            iv: toBase64(item.iv as Buffer),
            authTag: toBase64(item.authTag as Buffer),
        });
    } catch (error: any) {
        return res.status(500).json({ error: error.message });
    }
};

export const listItems = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user.userId;
        const items = await vaultService.getVaultItems(userId);

        const formatted = items.map((item) => ({
            ...item,
            encryptedBlob: toBase64(item.encryptedBlob as Buffer),
            iv: toBase64(item.iv as Buffer),
            authTag: toBase64(item.authTag as Buffer),
        }));

        return res.json(formatted);
    } catch (error: any) {
        return res.status(500).json({ error: error.message });
    }
};

export const getItem = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user.userId;
        const { id } = req.params;
        const item = await vaultService.getVaultItem(userId, id);

        if (!item) return res.status(404).json({ error: "Item not found" });

        return res.json({
            ...item,
            encryptedBlob: toBase64(item.encryptedBlob as Buffer),
            iv: toBase64(item.iv as Buffer),
            authTag: toBase64(item.authTag as Buffer),
        });
    } catch (error: any) {
        return res.status(500).json({ error: error.message });
    }
};

export const updateItem = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user.userId;
        const { id } = req.params;
        const { encryptedBlob, iv, authTag } = req.body;

        const item = await vaultService.updateVaultItem(
            userId,
            id,
            toBuffer(encryptedBlob),
            toBuffer(iv),
            toBuffer(authTag)
        );

        return res.json({
            ...item,
            encryptedBlob: toBase64(item.encryptedBlob as Buffer),
            iv: toBase64(item.iv as Buffer),
            authTag: toBase64(item.authTag as Buffer),
        });
    } catch (error: any) {
        return res.status(500).json({ error: error.message });
    }
};

export const deleteItem = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.user.userId;
        const { id } = req.params;
        await vaultService.deleteVaultItem(userId, id);
        return res.json({ message: "Item deleted" });
    } catch (error: any) {
        return res.status(500).json({ error: error.message });
    }
};
