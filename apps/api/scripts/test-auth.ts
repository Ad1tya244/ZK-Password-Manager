import fetch from "node-fetch-commonjs";
import dotenv from "dotenv";
import path from "path";
import { authenticator } from "@otplib/preset-default";

dotenv.config({ path: path.resolve(__dirname, "../../../packages/database/.env") });

const BASE_URL = "http://localhost:4000/auth";
const username = `user${Math.floor(Math.random() * 10000)}`;
const mobileNumber = "+1234567890";
const password = "Password123!";

async function runTests() {
    const { PrismaClient } = await import("@zk/database");
    const prisma = new PrismaClient();
    console.log("Starting Auth TOTP Tests...");
    let cookie = "";

    try {
        // 1. Register
        console.log(`\n1. Testing Register (${username})...`);
        const regRes = await fetch(`${BASE_URL}/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, mobileNumber, password }),
        });
        const regData = await regRes.json();
        console.log(`Status: ${regRes.status}`, regData);
        if (regRes.status !== 201) throw new Error("Register failed");

        // 2. Enable 2FA (Get Secret)
        console.log("\n2. Enabling 2FA...");
        const enableRes = await fetch(`${BASE_URL}/enable-2fa`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username }),
        });
        const enableData: any = await enableRes.json();
        console.log(`Status: ${enableRes.status}`, "Secret received");

        const secret = enableData.secret;
        if (!secret) throw new Error("Failed to get 2FA secret");

        // 3. Verify 2FA (Activates it)
        console.log("\n3. Verifying 2FA Setup...");
        const token = authenticator.generate(secret);
        const verifySetupRes = await fetch(`${BASE_URL}/verify-2fa`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, token, secret }),
        });
        const verifySetupData = await verifySetupRes.json();
        console.log(`Status: ${verifySetupRes.status}`, verifySetupData);
        if (verifySetupRes.status !== 200) throw new Error("2FA Setup Verification failed");

        // 4. Login (Should require 2FA)
        console.log("\n4. Testing Login (expecting 2FA challenge)...");
        const loginRes = await fetch(`${BASE_URL}/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });

        const loginData: any = await loginRes.json();
        console.log(`Status: ${loginRes.status}`, loginData);

        if (!loginData.require2fa) throw new Error("Login did not require 2FA");
        console.log("2FA Challenge Received.");

        // 5. Verify 2FA for Login
        console.log("\n5. Verifying 2FA for Login...");
        const loginToken = authenticator.generate(secret);
        const verifyLoginRes = await fetch(`${BASE_URL}/verify-2fa`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, token: loginToken }),
        });
        const verifyLoginData = await verifyLoginRes.json();
        console.log(`Status: ${verifyLoginRes.status}`, verifyLoginData);

        // Extract cookies
        const setCookie = verifyLoginRes.headers.get("set-cookie");
        if (setCookie) {
            console.log("Cookies received.");
            cookie = setCookie.split(',').map(c => c.split(';')[0]).join('; ');
        }

        if (verifyLoginRes.status !== 200) throw new Error("Login 2FA Verification failed");

        // 6. Me (Protected)
        console.log("\n6. Testing /me (Protected)...");
        const meRes = await fetch(`${BASE_URL}/me`, {
            headers: { Cookie: cookie },
        });
        const meData = await meRes.json();
        console.log(`Status: ${meRes.status}`, meData);
        if (meRes.status !== 200) throw new Error("Me failed");

        console.log("\nAll TOTP tests passed!");

    } catch (e) {
        console.error(e);
        process.exit(1);
    } finally {
        await prisma.$disconnect();
    }
}

runTests();
