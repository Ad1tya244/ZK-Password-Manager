import { Router } from "express";
import { register, login, enable2fa, verify2fa, logout, me, deleteAccount } from "../controllers/auth.controller";
import { authenticateToken } from "../middleware/auth.middleware";
import { loginLimiter } from "../middleware/rate-limit.middleware";

const router = Router();

router.post("/register", register);
router.post("/login", loginLimiter, login);
router.post("/enable-2fa", enable2fa);
router.post("/verify-2fa", loginLimiter, verify2fa);
router.post("/logout", logout);
router.get("/me", authenticateToken, me);
router.delete("/delete", authenticateToken, deleteAccount);

export default router;
