import { Redis } from "@upstash/redis";
import { Ratelimit } from "@upstash/ratelimit";

let ratelimit: Ratelimit | null = null;

if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    const redis = new Redis({
        url: process.env.UPSTASH_REDIS_REST_URL,
        token: process.env.UPSTASH_REDIS_REST_TOKEN,
    });

    ratelimit = new Ratelimit({
        redis,
        limiter: Ratelimit.slidingWindow(10, "60 s"),
        analytics: true,
        prefix: "@upstash/ratelimit",
    });
} else {
    console.warn("Upstash Redis environment variables (UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN) are missing. Rate limiting is bypassed.");
}

/**
 * Returns true if the request is allowed, false if it should be rate-limited.
 */
export async function checkRateLimit(key: string): Promise<boolean> {
    if (!ratelimit) {
        return true;
    }
    try {
        const { success } = await ratelimit.limit(key);
        return success;
    } catch (error: unknown) {
        console.error("Rate limiting evaluation error:", error);
        // Fail-open for high availability
        return true;
    }
}

/**
 * Convenience helper that returns a 429 Response when rate-limited, or null when allowed.
 */
export async function rateLimitResponse(key: string): Promise<Response | null> {
    const allowed = await checkRateLimit(key);
    if (allowed) return null;
    return Response.json(
        { error: "Too many attempts from this device or network. Please try again in 1 minute." },
        { status: 429 }
    );
}
