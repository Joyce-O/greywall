/**
 * Demo Express app that:
 * 1. Serves an API on port 3000
 * 2. Connects to Redis on localhost:6379
 * 3. Attempts to call external APIs (blocked by greywall)
 *
 * This demonstrates allowLocalOutbound - the app can reach
 * local services (Redis) but not the external internet.
 */

import express from "express";
import Redis from "ioredis";
import { ProxyAgent, fetch as undiciFetch } from "undici";

const app = express();
const PORT = 3000;

// Connect to Redis on localhost
const redis = new Redis({
  host: "127.0.0.1",
  port: 6379,
  connectTimeout: 3000,
  retryStrategy: () => null, // Don't retry, fail fast for demo
});

let redisConnected = false;

redis.on("connect", () => {
  redisConnected = true;
  console.log("[app] Connected to Redis");

  // Seed some demo data
  redis.set(
    "user:1",
    JSON.stringify({ id: 1, name: "Alice", email: "alice@example.com" })
  );
  redis.set(
    "user:2",
    JSON.stringify({ id: 2, name: "Bob", email: "bob@example.com" })
  );
  redis.set(
    "user:3",
    JSON.stringify({ id: 3, name: "Charlie", email: "charlie@example.com" })
  );
  console.log("[app] Seeded demo data");
});

redis.on("error", (err) => {
  if (!redisConnected) {
    console.log("[app] Redis connection failed:", err.message);
  }
});

// Helper: Make external API call using undici with proxy support
// Node.js native https doesn't respect HTTP_PROXY, so we use undici
async function fetchExternal(url) {
  const proxyUrl = process.env.HTTPS_PROXY || process.env.HTTP_PROXY;

  const options = {
    signal: AbortSignal.timeout(5000),
  };

  // Use proxy if available (set by greywall)
  if (proxyUrl) {
    options.dispatcher = new ProxyAgent(proxyUrl);
  }

  const response = await undiciFetch(url, options);
  const text = await response.text();

  return {
    status: response.status,
    data: text.slice(0, 200),
  };
}

// Routes

app.get("/", (req, res) => {
  res.json({
    message: "Dev Server Demo",
    redis: redisConnected ? "connected" : "disconnected",
    endpoints: {
      "/api/users": "List all users from Redis",
      "/api/users/:id": "Get user by ID from Redis",
      "/api/health": "Health check",
      "/api/external": "Try to call external API (blocked by greywall)",
    },
  });
});

app.get("/api/users", async (req, res) => {
  if (!redisConnected) {
    return res.status(503).json({
      error: "Redis not connected",
      hint: "Start Redis: docker run -p 6379:6379 redis:alpine",
    });
  }

  try {
    const keys = await redis.keys("user:*");
    const users = await Promise.all(
      keys.map(async (key) => JSON.parse(await redis.get(key)))
    );
    res.json({
      source: "redis",
      count: users.length,
      data: users,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/users/:id", async (req, res) => {
  if (!redisConnected) {
    return res.status(503).json({
      error: "Redis not connected",
      hint: "Start Redis: docker run -p 6379:6379 redis:alpine",
    });
  }

  try {
    const user = await redis.get(`user:${req.params.id}`);
    if (user) {
      res.json({ source: "redis", data: JSON.parse(user) });
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/health", async (req, res) => {
  if (!redisConnected) {
    return res.status(503).json({
      status: "unhealthy",
      redis: "disconnected",
    });
  }

  try {
    await redis.ping();
    res.json({
      status: "healthy",
      redis: "connected",
    });
  } catch (error) {
    res.status(503).json({
      status: "unhealthy",
      redis: "error",
      error: error.message,
    });
  }
});

app.get("/api/external", async (req, res) => {
  console.log("[app] Attempting external API call...");

  try {
    const result = await fetchExternal("https://httpbin.org/get");
    // Check if we're using a proxy (indicates greywall is running)
    const usingProxy = !!(process.env.HTTPS_PROXY || process.env.HTTP_PROXY);
    res.json({
      status: "success",
      message: usingProxy
        ? "✓ Request allowed (httpbin.org is whitelisted)"
        : "⚠️ No proxy detected - not running in greywall",
      proxy: usingProxy ? process.env.HTTPS_PROXY : null,
      data: result,
    });
  } catch (error) {
    res.json({
      status: "blocked",
      message: "✓ External call blocked by greywall",
      error: error.message,
    });
  }
});

// Startup

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║  Dev Server Demo                                          ║
╠═══════════════════════════════════════════════════════════╣
║  Server:  http://localhost:${PORT}                        ║
║  Redis:   localhost:6379                                  ║
╠═══════════════════════════════════════════════════════════╣
║  Endpoints:                                               ║
║    GET /              - API info                          ║
║    GET /api/users     - List users from Redis             ║
║    GET /api/users/:id - Get user by ID                    ║
║    GET /api/health    - Health check                      ║
║    GET /api/external  - Try external call (blocked)       ║
╚═══════════════════════════════════════════════════════════╝
  `);
});
