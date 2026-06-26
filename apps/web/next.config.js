const path = require("path");

/** @type {import('next').NextConfig} */
const nextConfig = {
    poweredByHeader: false,
    experimental: {
        serverComponentsExternalPackages: ["argon2"],
        outputFileTracingRoot: path.join(__dirname, "../../"),
        outputFileTracingIncludes: {
            "/api/**/*": ["../../node_modules/argon2/prebuilds/**/*"],
        },
    },
    async headers() {
        const isProd = process.env.NODE_ENV === "production";
        const cspValue = isProd
            ? "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';"
            : "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws://localhost:* http://localhost:* ws://127.0.0.1:* http://127.0.0.1:*; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';";

        const securityHeaders = [
            {
                key: "Content-Security-Policy",
                value: cspValue,
            },
            {
                key: "X-Frame-Options",
                value: "DENY",
            },
            {
                key: "X-Content-Type-Options",
                value: "nosniff",
            },
            {
                key: "Referrer-Policy",
                value: "strict-origin-when-cross-origin",
            },
            {
                key: "Permissions-Policy",
                value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
            },
        ];

        // Enable Strict-Transport-Security ONLY in production environment
        if (isProd) {
            securityHeaders.push({
                key: "Strict-Transport-Security",
                value: "max-age=31536000; includeSubDomains; preload",
            });
        }

        return [
            {
                source: "/:path*",
                headers: securityHeaders,
            },
        ];
    },
};

module.exports = nextConfig;

