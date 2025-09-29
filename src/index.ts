import "dotenv/config";
import { initializeTelemetry } from "./helpers/otel.js";
initializeTelemetry();

import express, { Request, Response } from "express";
import { createRequire } from "node:module";
import { trace, SpanStatusCode } from "@opentelemetry/api";
import { StreamableHTTPServer } from "./server.js";
import { logger } from "./helpers/logs.js";
import { securityMiddlewares } from "./server-middlewares.js";

const MCP_ENDPOINT = "/mcp";

const log = logger("index");
const server = new StreamableHTTPServer();
const app = express();
const router = express.Router();
app.use(MCP_ENDPOINT, securityMiddlewares);

const require = createRequire(import.meta.url);
const pkg = require("../package.json");

app.get("/", (req: Request, res: Response) => {
  const tracer = trace.getTracer('http-server');
  const span = tracer.startSpan('http.health_check', {
    attributes: {
      'http.method': req.method,
      'http.route': '/',
      'http.user_agent': req.get('user-agent') || 'unknown',
      'http.remote_addr': (req as any).ip || 'unknown',
    },
  });
  
  try {
    const now = new Date();
    const uptime = Math.round(process.uptime());
    const memoryUsage = process.memoryUsage();
    
    const healthData = {
      status: "ok",
      name: pkg.name || "mcp-server",
      version: pkg.version || "unknown",
      endpoint: MCP_ENDPOINT,
      uptimeSeconds: uptime,
      timestamp: now.toISOString(),
      environment: process.env.NODE_ENV || "development",
      pid: process.pid,
      memory: {
        rss: memoryUsage.rss,
        heapUsed: memoryUsage.heapUsed,
      },
    };
    
    span.setAttributes({
      'health.status': healthData.status,
      'health.uptime_seconds': uptime,
      'health.memory_rss': memoryUsage.rss,
      'health.memory_heap_used': memoryUsage.heapUsed,
      'health.pid': process.pid,
      'http.response.status_code': 200,
    });
    
    span.addEvent('health.check_completed', {
      'uptime_seconds': uptime,
      'memory_usage_mb': Math.round(memoryUsage.heapUsed / 1024 / 1024),
    });
    
    span.setStatus({
      code: SpanStatusCode.OK,
      message: 'Health check successful',
    });
    
    res.setHeader("Cache-Control", "no-store");
    res.status(200).json(healthData);
  } catch (error) {
    span.addEvent('health.check_error', {
      'error.message': error instanceof Error ? error.message : String(error),
    });
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    log.error('Health check error:', error);
    res.status(500).json({ error: 'Health check failed' });
  } finally {
    span.end();
  }
});

router.all(MCP_ENDPOINT, async (req: Request, res: Response) => {
  const tracer = trace.getTracer('http-server');
  const span = tracer.startSpan('http.mcp_request', {
    attributes: {
      'http.method': req.method,
      'http.route': MCP_ENDPOINT,
      'http.user_agent': req.get('user-agent') || 'unknown',
      'http.remote_addr': (req as any).ip || 'unknown',
      'http.content_type': req.get('content-type') || 'unknown',
      'http.content_length': req.get('content-length') || 0,
    },
  });
  
  try {
    const startTime = Date.now();
    
    span.addEvent('mcp.request_started', {
      'request.method': req.method,
      'request.content_type': req.get('content-type') || 'unknown',
    });
    
    await server.handleStreamableHTTP(req, res);
    
    const processingTime = Date.now() - startTime;
    
    span.setAttributes({
      'http.processing_time_ms': processingTime,
      'http.response.status_code': (res as any).statusCode,
      'mcp.request_success': true,
    });
    
    span.addEvent('mcp.request_completed', {
      'processing_time_ms': processingTime,
      'response_status': (res as any).statusCode,
    });
    
    span.setStatus({
      code: SpanStatusCode.OK,
      message: 'MCP request processed successfully',
    });
  } catch (error) {
    span.addEvent('mcp.request_error', {
      'error.message': error instanceof Error ? error.message : String(error),
      'error.name': error instanceof Error ? error.name : 'unknown',
    });
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    log.error('MCP request error:', error);
    
    if (!(res as any).headersSent) {
      (res as any).status(500).json({ error: 'Internal server error' });
    }
  } finally {
    span.end();
  }
});

app.use("/", router);

const PORT = process.env.PORT || 3000;
const tracer = trace.getTracer('http-server');
const serverSpan = tracer.startSpan('http.server_startup', {
  attributes: {
    'server.port': Number(PORT),
    'server.endpoint': MCP_ENDPOINT,
    'server.name': pkg.name || 'mcp-server',
    'server.version': pkg.version || 'unknown',
  },
});

try {
  app.listen(PORT, () => {
    log.success(`MCP Stateless Streamable HTTP Server`);
    log.success(`MCP endpoint: http://localhost:${PORT}${MCP_ENDPOINT}`);
    log.success(`Health check: http://localhost:${PORT}/`);
    log.success(`Press Ctrl+C to stop the server`);
  });
} catch (error) {
  serverSpan.addEvent('server.startup_error', {
    'error.message': error instanceof Error ? error.message : String(error),
  });
  serverSpan.setStatus({
    code: SpanStatusCode.ERROR,
    message: error instanceof Error ? error.message : String(error),
  });
  log.error('Server startup error:', error);
  throw error;
} finally {
  serverSpan.end();
}

process.on("SIGINT", async () => {
  const shutdownSpan = tracer.startSpan('http.server_shutdown', {
    attributes: {
      'shutdown.signal': 'SIGINT',
      'server.uptime_seconds': Math.round(process.uptime()),
    },
  });
  
  try {
    log.error("Shutting down server...");
    
    shutdownSpan.addEvent('shutdown.started', {
      'uptime_seconds': Math.round(process.uptime()),
    });
    
    const shutdownStart = Date.now();
    await server.close();
    const shutdownTime = Date.now() - shutdownStart;
    
    shutdownSpan.setAttributes({
      'shutdown.success': true,
      'shutdown.time_ms': shutdownTime,
    });
    
    shutdownSpan.addEvent('shutdown.completed', {
      'shutdown_time_ms': shutdownTime,
    });
    
    shutdownSpan.setStatus({
      code: SpanStatusCode.OK,
      message: 'Server shutdown completed',
    });
    
    log.success('Server shutdown completed successfully');
    process.exit(0);
  } catch (error) {
    shutdownSpan.addEvent('shutdown.error', {
      'error.message': error instanceof Error ? error.message : String(error),
    });
    shutdownSpan.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    log.error('Error during shutdown:', error);
    process.exit(1);
  } finally {
    shutdownSpan.end();
  }
});
