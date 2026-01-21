import { Request, Response, NextFunction } from "express";
import { verifyToken } from "@zk/crypto";

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies.accessToken;

    if (!token) {
        return res.status(401).json({ error: "Access denied. No token provided." });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(403).json({ error: "Invalid token." });
    }

    // @ts-ignore
    req.user = decoded;
    next();
};
