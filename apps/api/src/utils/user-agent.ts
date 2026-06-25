export function parseUserAgent(userAgent: string | undefined | null): string {
    if (!userAgent) return "Unknown Device";
    
    let os = "Unknown OS";
    let browser = "Unknown Browser";
    const ua = userAgent.toLowerCase();

    // Operating System
    if (ua.includes("windows")) os = "Windows";
    else if (ua.includes("macintosh") || ua.includes("mac os") || ua.includes("macintel")) os = "macOS";
    else if (ua.includes("iphone") || ua.includes("ipad") || ua.includes("ipod")) os = "iOS";
    else if (ua.includes("android")) os = "Android";
    else if (ua.includes("linux")) os = "Linux";

    // Browser
    if (ua.includes("firefox")) browser = "Firefox";
    else if (ua.includes("opera") || ua.includes("opr/")) browser = "Opera";
    else if (ua.includes("edge") || ua.includes("edg/")) browser = "Edge";
    else if (ua.includes("chrome") && !ua.includes("chromium")) browser = "Chrome";
    else if (ua.includes("safari") && !ua.includes("chrome") && !ua.includes("chromium")) browser = "Safari";
    else if (ua.includes("chromium")) browser = "Chromium";

    return `${browser} on ${os}`;
}
