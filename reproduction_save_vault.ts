
import fetch from "node-fetch-commonjs";
import { authenticator } from "@otplib/preset-default";

const BASE_URL = "http://127.0.0.1:4000";
const username = `testuser${Date.now()}`;
const password = "Password123!";
const mobileNumber = "+1234567890";

async function run() {
    try {
        console.log("1. Registering...");
        const regRes = await fetch(`${BASE_URL}/auth/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, mobileNumber, password }),
        });
        if (regRes.status !== 201) throw new Error(`Register failed: ${await regRes.text()}`);

        console.log("2. Logging in...");
        const loginRes = await fetch(`${BASE_URL}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });
        const loginData = await loginRes.json();

        // Handle 2FA if needed (shouldn't be needed for fresh user unless enabled)
        // Parse cookies properly. set-cookie can be multiple headers or comma separated.
        const rawCookies = loginRes.headers.raw()['set-cookie'];
        const cookies = rawCookies.map((c: string) => c.split(';')[0]).join('; ');

        console.log("Parsed Cookies:", cookies);
        if (!cookies.includes("accessToken")) throw new Error("No accessToken received");

        console.log("3. Saving Vault Item...");
        // Mock encrypted data (usually done by client)
        const mockData = {
            encryptedBlob: Buffer.from("mock_encrypted_data").toString("base64"),
            iv: Buffer.from("mock_iv_12bytes").toString("base64"),
            authTag: Buffer.from("mock_tag_16bytes").toString("base64"),
        };

        const saveRes = await fetch(`${BASE_URL}/vault`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Cookie": cookies
            },
            body: JSON.stringify(mockData),
        });

        const saveText = await saveRes.text();
        console.log(`Save Status: ${saveRes.status}`);
        console.log(`Save Response: ${saveText}`);

    } catch (e) {
        console.error("Error:", e);
    }
}

run();
