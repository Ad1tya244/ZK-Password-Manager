import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = process.env.PORT || 4000;

import authRoutes from "./routes/auth.routes";
import vaultRoutes from "./routes/vault.routes";

app.use(cors({
    origin: ["http://localhost:3000", "http://127.0.0.1:3000"],
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

app.use("/auth", authRoutes);
app.use("/vault", vaultRoutes);

app.get("/health", (req, res) => {
    res.json({ status: "ok" });
});

app.listen(Number(port), "0.0.0.0", () => {
    console.log(`API running on port ${port} (0.0.0.0)`);
});
