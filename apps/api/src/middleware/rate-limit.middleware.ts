import rateLimit from "express-rate-limit";

export const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10, // Limit each IP to 5 login requests per window
    message: { error: "Too many attempts from this device or network. Please try again in 1 minute" },
    standardHeaders: true,
    legacyHeaders: false,
});
