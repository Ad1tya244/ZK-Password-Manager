import jwt from "jsonwebtoken";

if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET environment variable is not set. Set it before starting the server.");
}
const JWT_SECRET = process.env.JWT_SECRET;

export interface TokenPayload {
    userId: string;
    username: string;
}

export const generateToken = (payload: TokenPayload): string => {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: "15m" });
};

export const verifyToken = (token: string): jwt.JwtPayload | null => {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return typeof decoded === "string" ? null : decoded;
    } catch (error) {
        return null;
    }
};

export const generateRefreshToken = (payload: { userId: string }): string => {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
};
