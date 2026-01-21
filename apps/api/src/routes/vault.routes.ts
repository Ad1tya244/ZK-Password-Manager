import { Router } from "express";
import * as vaultController from "../controllers/vault.controller";
import { authenticateToken } from "../middleware/auth.middleware";

const router = Router();

router.use(authenticateToken); // Protect all vault routes

router.post("/", vaultController.createItem);
router.get("/", vaultController.listItems);
router.get("/:id", vaultController.getItem);
router.put("/:id", vaultController.updateItem);
router.delete("/:id", vaultController.deleteItem);

export default router;
