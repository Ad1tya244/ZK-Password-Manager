import { Request, Response, NextFunction } from "express";
import { verifyToken } from "@zk/crypto";
import { PrismaClient } from "@zk/database";
import crypto from "crypto";

const prisma = new PrismaClient();

export const authenticateToken = async (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies.accessToken;

    if (!token) {
        return res.status(401).json({ error: "Access denied. No token provided." });
    }

    const decoded = verifyToken(token);
    if (!decoded || typeof decoded !== "object") {
        return res.status(403).json({ error: "Invalid token." });
    }

    const { userId } = decoded as { userId: string };
    if (!userId) {
        return res.status(403).json({ error: "Invalid token payload." });
    }

    // Compute the SHA-256 hash of the session/JWT token
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    try {
        // Fetch the session from the database
        const session = await prisma.session.findUnique({
            where: { tokenHash },
        });

        // Check if the session exists, belongs to the correct user, and has not expired
        if (!session || session.userId !== userId || session.expiresAt < new Date()) {
            if (session && session.expiresAt < new Date()) {
                // Auto clean up this expired session
                await prisma.session.delete({ where: { tokenHash } }).catch(() => {});
            }
            return res.status(401).json({ error: "Session expired or invalid. Please login again." });
        }

        // Clean up all other expired sessions for this user to prevent accumulation
        await prisma.session.deleteMany({
            where: {
                userId,
                expiresAt: { lt: new Date() }
            }
        }).catch(() => {});

    } catch (dbError) {
        console.error("Database error during token verification:", dbError);
        return res.status(500).json({ error: "Internal server error during authentication" });
    }

    // @ts-ignore
    req.user = decoded;
    next();
};
