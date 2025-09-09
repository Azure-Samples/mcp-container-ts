import "dotenv/config";
import express, { Request, Response } from "express";
import { createRequire } from "node:module";
import { StreamableHTTPServer } from "./server.js";
import { logger } from "./helpers/logs.js";
import { securityMiddlewares } from "./server-middlewares.js";
import { initializeTelemetry } from "./helpers/azure-monitor.js";
initializeTelemetry();

const log = logger("index");

const server = new StreamableHTTPServer();

const MCP_ENDPOINT = "/mcp";
const app = express();
const router = express.Router();
app.use(MCP_ENDPOINT, securityMiddlewares);

// Basic health / readiness endpoint (no auth) for probes & users
const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-var-requires
const pkg = require("../package.json");

app.get("/", (req: Request, res: Response) => {
  const now = new Date();
  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({
    status: "ok",
    name: pkg.name || "mcp-server",
    version: pkg.version || "unknown",
    endpoint: MCP_ENDPOINT,
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: now.toISOString(),
    environment: process.env.NODE_ENV || "development",
    pid: process.pid,
    memory: {
      rss: process.memoryUsage().rss,
      heapUsed: process.memoryUsage().heapUsed,
    },
  });
});

router.all(MCP_ENDPOINT, async (req: Request, res: Response) => {
  await server.handleStreamableHTTP(req, res);
});

app.use("/", router);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  log.success(`MCP Stateless Streamable HTTP Server`);
  log.success(`MCP endpoint: http://localhost:${PORT}${MCP_ENDPOINT}`);
  log.success(`Press Ctrl+C to stop the server`);
});

process.on("SIGINT", async () => {
  log.error("Shutting down server...");
  await server.close();
  process.exit(0);
});
