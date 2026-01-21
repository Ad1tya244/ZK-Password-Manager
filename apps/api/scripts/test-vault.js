const fetch = require("node-fetch-commonjs");

const BASE_URL = "http://localhost:4000";
const email = `vault-test-${Date.now()}@example.com`;
const password = "securepassword123";

async function runTests() {
    console.log("Starting Vault Tests...");
    let cookie = "";

    // 1. Register & Login to get Cookies
    console.log("\n1. Authentication...");
    await fetch(`${BASE_URL}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
    });

    const loginRes = await fetch(`${BASE_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
    });

    const setCookie = loginRes.headers.get("set-cookie");
    if (!setCookie) throw new Error("Login failed (no cookie)");
    cookie = setCookie.split(',').map(c => c.split(';')[0]).join('; ');

    // 2. Create Vault Item
    console.log("\n2. Create Vault Item...");
    const itemData = {
        encryptedBlob: Buffer.from("encrypted-secret").toString("base64"),
        iv: Buffer.from("12-byte-iv-vec").toString("base64"),
        authTag: Buffer.from("16-byte-tag-val").toString("base64")
    };

    const createRes = await fetch(`${BASE_URL}/vault`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Cookie: cookie
        },
        body: JSON.stringify(itemData)
    });
    const createdItem = await createRes.json();
    console.log("Created:", createdItem);
    if (createRes.status !== 201) throw new Error("Create failed");
    const itemId = createdItem.id;

    // 3. List Items
    console.log("\n3. List Items...");
    const listRes = await fetch(`${BASE_URL}/vault`, {
        headers: { Cookie: cookie }
    });
    const items = await listRes.json();
    console.log("Items:", items.length);
    if (items.length !== 1) throw new Error("List failed");

    // 4. Update Item
    console.log("\n4. Update Item...");
    const updateRes = await fetch(`${BASE_URL}/vault/${itemId}`, {
        method: "PUT",
        headers: {
            "Content-Type": "application/json",
            Cookie: cookie
        },
        body: JSON.stringify({
            ...itemData,
            encryptedBlob: Buffer.from("updated-secret").toString("base64")
        })
    });
    const updatedItem = await updateRes.json();
    console.log("Updated:", updatedItem.encryptedBlob);
    if (updatedItem.encryptedBlob === itemData.encryptedBlob) throw new Error("Update failed");

    // 5. Delete Item
    console.log("\n5. Delete Item...");
    const deleteRes = await fetch(`${BASE_URL}/vault/${itemId}`, {
        method: "DELETE",
        headers: { Cookie: cookie }
    });
    console.log("Delete Status:", deleteRes.status);

    // Verify Deletion
    const getRes = await fetch(`${BASE_URL}/vault/${itemId}`, {
        headers: { Cookie: cookie }
    });
    if (getRes.status !== 404) throw new Error("Delete failed (item still exists)");

    console.log("\nAll Vault tests passed!");
}

runTests().catch(err => {
    console.error(err);
    process.exit(1);
});
