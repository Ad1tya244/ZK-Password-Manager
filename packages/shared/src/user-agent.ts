export interface UserAgentMetadata {
    browser: string;
    os: string;
    device: "Mobile" | "Desktop" | "Tablet" | "Unknown";
}

export function parseUserAgent(userAgent: string | undefined | null): UserAgentMetadata {
    if (!userAgent) {
        return { browser: "Unknown", os: "Unknown", device: "Unknown" };
    }

    const ua = userAgent.toLowerCase();
    let os = "Unknown";
    let browser = "Unknown";
    let device: "Mobile" | "Desktop" | "Tablet" | "Unknown" = "Unknown";

    // 1. Identify Operating System
    if (ua.includes("windows")) {
        os = "Windows";
        device = "Desktop";
    } else if (ua.includes("android")) {
        os = "Android";
        device = (ua.includes("ipad") || ua.includes("tablet") || ua.includes("playbook")) ? "Tablet" : "Mobile";
    } else if (ua.includes("iphone") || ua.includes("ipod")) {
        os = "iOS";
        device = "Mobile";
    } else if (ua.includes("ipad")) {
        os = "iOS";
        device = "Tablet";
    } else if (ua.includes("macintosh") || ua.includes("mac os") || ua.includes("macintel")) {
        // Distinguish iOS (iPadOS 13+) presenting as macOS (crios, fxios, edgios, opios, mobile, touch, tablet)
        if (
            ua.includes("crios") ||
            ua.includes("fxios") ||
            ua.includes("edgios") ||
            ua.includes("opios") ||
            ua.includes("mobile") ||
            ua.includes("touch") ||
            ua.includes("tablet")
        ) {
            os = "iOS";
            device = (ua.includes("ipad") || ua.includes("tablet")) ? "Tablet" : "Mobile";
        } else {
            os = "macOS";
            device = "Desktop";
        }
    } else if (ua.includes("linux")) {
        os = "Linux";
        device = "Desktop";
    }

    // 2. Identify Browser (order is critical to resolve compatibility tokens)
    if (ua.includes("opera") || ua.includes("opr/") || ua.includes("opios")) {
        browser = "Opera";
    } else if (ua.includes("edge") || ua.includes("edg/") || ua.includes("edgios") || ua.includes("edga/")) {
        browser = "Edge";
    } else if (ua.includes("firefox") || ua.includes("fxios")) {
        browser = "Firefox";
    } else if (ua.includes("chromium")) {
        browser = "Chromium";
    } else if (ua.includes("chrome") || ua.includes("crios")) {
        browser = "Chrome";
    } else if (ua.includes("safari")) {
        browser = "Safari";
    }

    // If one of the core fields is not parsed correctly, resolve as unknown device
    if (os === "Unknown" || browser === "Unknown") {
        // Support legacy preformatted strings check if they can be mapped
        // E.g. "Chrome on macOS" or similar
        if (userAgent.includes(" on ")) {
            const parts = userAgent.split(" on ");
            if (parts.length === 2) {
                const legacyBrowser = parts[0].trim();
                const legacyOS = parts[1].trim();
                const validBrowsers = ["Chrome", "Safari", "Edge", "Firefox", "Opera", "Chromium"];
                const validOS = ["Windows", "macOS", "Linux", "Android", "iOS"];
                if (validBrowsers.includes(legacyBrowser) && validOS.includes(legacyOS)) {
                    os = legacyOS;
                    browser = legacyBrowser;
                    device = (os === "iOS" || os === "Android") ? "Mobile" : "Desktop";
                }
            }
        }
    }

    if (os === "Unknown" || browser === "Unknown") {
        return { browser: "Unknown", os: "Unknown", device: "Unknown" };
    }

    return { browser, os, device };
}
