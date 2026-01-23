import { Router } from "express";
import * as authController from "../controllers/auth.controller";
import { authenticateToken } from "../middleware/auth.middleware";
import { loginLimiter } from "../middleware/rate-limit.middleware";

const router = Router();

router.post("/register", authController.register);
router.post("/login", loginLimiter, authController.login);
router.post("/enable-2fa", authController.enable2fa);
router.post("/verify-2fa", loginLimiter, authController.verify2fa);
router.post("/logout", authController.logout);
router.get("/me", authenticateToken, authController.me);
router.delete("/delete", authenticateToken, authController.deleteAccount);
router.post("/verify-password", authenticateToken, authController.verifyPassword);

router.post("/vek", authenticateToken, authController.saveVEK);
router.post("/recovery/setup", authenticateToken, authController.setupRecovery);
router.post("/recovery/init", loginLimiter, authController.initRecovery);
router.post("/recovery/reset", loginLimiter, authController.recoverAccount);

export default router;
