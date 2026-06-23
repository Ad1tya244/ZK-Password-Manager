/**
 * Simple in-memory rate limiter.
 * Resets on server cold-start. Sufficient for single-instance / moderate traffic.
 * Upgrade to Upstash Redis rate limiting for multi-instance production scale.
 */

interface RateLimitEntry {
    count: number;
    resetAt: number;
}

const store = new Map<string, RateLimitEntry>();
const MAX_STORE_SIZE = 10_000;

// Periodic cleanup of expired entries every 60 seconds
if (typeof globalThis !== "undefined") {
    const cleanup = () => {
        const now = Date.now();
        store.forEach((entry, key) => {
            if (now > entry.resetAt) {
                store.delete(key);
            }
        });
    };
    const interval = setInterval(cleanup, 60_000);
    if (interval && typeof interval.unref === "function") {
        interval.unref();
    }
}

/**
 * Returns true if the request is allowed, false if it should be rate-limited.
 * Default: 10 requests per 60 seconds per key (usually an IP address).
 */
export function checkRateLimit(
    key: string,
    limit = 10,
    windowMs = 60_000
): boolean {
    const now = Date.now();

    // Inline protection against unbounded Map growth under high volume or DoS attacks
    if (store.size > MAX_STORE_SIZE) {
        store.forEach((e, k) => {
            if (now > e.resetAt) {
                store.delete(k);
            }
        });
        // If still exceeding size limit, clear the map entirely to prevent OOM
        if (store.size > MAX_STORE_SIZE) {
            store.clear();
        }
    }

    const entry = store.get(key);

    if (!entry || now > entry.resetAt) {
        store.set(key, { count: 1, resetAt: now + windowMs });
        return true;
    }

    if (entry.count >= limit) {
        return false;
    }

    entry.count++;
    return true;
}

/**
 * Convenience helper that returns a 429 Response when rate-limited, or null when allowed.
 */
export function rateLimitResponse(key: string): Response | null {
    if (checkRateLimit(key)) return null;
    return Response.json(
        { error: "Too many attempts from this device or network. Please try again in 1 minute." },
        { status: 429 }
    );
}
