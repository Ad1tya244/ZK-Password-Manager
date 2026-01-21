import { PrismaClient } from "@zk/database";

const prisma = new PrismaClient();

export const createVaultItem = async (userId: string, data: Buffer, iv: Buffer, authTag: Buffer) => {
    return await prisma.vault.create({
        data: {
            userId,
            encryptedBlob: data,
            iv,
            authTag,
        },
    });
};

export const getVaultItems = async (userId: string) => {
    return await prisma.vault.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
    });
};

export const getVaultItem = async (userId: string, id: string) => {
    return await prisma.vault.findFirst({
        where: { id, userId },
    });
};

export const updateVaultItem = async (userId: string, id: string, data: Buffer, iv: Buffer, authTag: Buffer) => {
    // Verify ownership
    const existing = await prisma.vault.findFirst({ where: { id, userId } });
    if (!existing) throw new Error("Item not found");

    return await prisma.vault.update({
        where: { id },
        data: {
            encryptedBlob: data,
            iv,
            authTag,
        },
    });
};

export const deleteVaultItem = async (userId: string, id: string) => {
    const existing = await prisma.vault.findFirst({ where: { id, userId } });
    if (!existing) throw new Error("Item not found");

    return await prisma.vault.delete({
        where: { id },
    });
};
