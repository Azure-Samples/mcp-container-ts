import helmet from "helmet";
import timeout from "connect-timeout";
import cors from "cors";
import { body, validationResult } from "express-validator";
import rateLimit from "express-rate-limit";
import express, { NextFunction, Request, Response } from "express";
import { trace, SpanStatusCode } from "@opentelemetry/api";
import { authenticateJWT } from "./auth/jwt.js";
import { logger } from "./helpers/logs.js";

const log = logger("middleware");

// Middleware to limite the number of requests from a single IP address
const rateLimiterMiddleware = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: "Too many requests from this IP",
    retryAfter: 900, // 15 minutes in seconds
  },
  standardHeaders: true,
  legacyHeaders: false,
  // OpenAI API uses X-Forwarded-For header to pass the original client IP
  // We need to disable the validation of this header otherwise it will reject requests
  validate: { xForwardedForHeader: false },
  handler: (req: Request, res: Response, next: NextFunction, options) => {
    
    log.info("headers",{ ...req.headers });
    log.info("ip", (req as any).ip);
    log.info("user-agent", req.get("user-agent"));
    log.info("request.url", req.originalUrl);

    const tracer = trace.getTracer("rate_limiter");
    const span = tracer.startSpan("middleware.rate_limiter", {
      attributes: {
        "request.method": (req as any).method || "unknown",
        "request.url":
          (req as any).originalUrl || (req as any).url || "unknown",
        "rate_limiter.max_requests": (options.limit as number) || 100,
        "rate_limiter.window_ms": options.windowMs || 900000,
      },
    });
    try {
      span.addEvent("rate_limiter.request_blocked", {
        "rate_limiter.message": options.message
          ? JSON.stringify(options.message)
          : "Too many requests",
      });
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: "Too many requests from this IP",
      });
      log.warn("Rate limit exceeded", { ip: (req as any).ip });
      (res as any).status(429).json(
        options.message || {
          error: "Too many requests from this IP",
          retryAfter: Math.round((options.windowMs || 900000) / 1000),
        }
      );
    } catch (error) {
      span.addEvent("rate_limiter.handler_error", {
        "error.message": error instanceof Error ? error.message : String(error),
      });
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : String(error),
      });
      throw error;
    } finally {
      span.end();
    }

    next();
  },
});

// CORS configuration
const corsMiddleware = cors({
  origin: process.env.ALLOWED_ORIGINS?.split(",") || ["https://localhost:3000"],
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
});

// Helmet middleware for security
const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
});

// Middleware to parse JSON bodies with tracing
const jsonMiddleware = [
  (req: Request, res: Response, next: NextFunction) => {
    const tracer = trace.getTracer("middleware");
    const span = tracer.startSpan("middleware.json_parsing", {
      attributes: {
        "request.method": (req as any).method || "unknown",
        "request.content_type": req.get("content-type") || "unknown",
      },
    });

    const startTime = Date.now();

    express.json({
      limit: "10mb",
      verify: (req, res, buf) => {
        const bodySize = buf.length;
        span.setAttributes({
          "request.body_size_bytes": bodySize,
        });

        if (bodySize > 10 * 1024 * 1024) {
          span.addEvent("request.body_too_large", {
            body_size_bytes: bodySize,
            limit_bytes: 10 * 1024 * 1024,
          });
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: "Request body too large",
          });
          throw new Error("Request body too large");
        }
      },
    })(req, res, (err) => {
      const processingTime = Date.now() - startTime;

      span.setAttributes({
        processing_time_ms: processingTime,
      });

      if (err) {
        span.addEvent("json.parsing_error", {
          "error.message": err.message,
          processing_time_ms: processingTime,
        });
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: err.message,
        });
      } else {
        span.addEvent("json.parsing_success", {
          processing_time_ms: processingTime,
        });
        span.setStatus({
          code: SpanStatusCode.OK,
          message: "JSON parsing completed",
        });
      }

      span.end();
      next(err);
    });
  },
];

// Middleware to parse URL-encoded bodies
const urlencodedMiddleware = express.urlencoded({
  extended: true,
  limit: "10mb",
  parameterLimit: 1000,
});

// Middleware to handle request timeouts
const timeoutMiddleware = [
  timeout("30s"),
  (req: Request, res: Response, next: NextFunction) => {
    const tracer = trace.getTracer("middleware");
    const span = tracer.startSpan("middleware.timeout_check", {
      attributes: {
        "request.method": (req as any).method || "unknown",
        "request.url":
          (req as any).originalUrl || (req as any).url || "unknown",
        "request.timeout_ms": 30000,
      },
    });

    try {
      if (req.timedout) {
        span.addEvent("request.timeout_occurred", {
          timeout_duration_ms: 30000,
        });
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: "Request timeout",
        });
        log.warn("Request timed out");
      } else {
        span.addEvent("request.within_timeout");
        span.setStatus({
          code: SpanStatusCode.OK,
          message: "Request within timeout limits",
        });
      }

      if (!req.timedout) next();
    } catch (error) {
      span.addEvent("middleware.timeout_error", {
        "error.message": error instanceof Error ? error.message : String(error),
      });
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : String(error),
      });
      throw error;
    } finally {
      span.end();
    }
  },
];

// Middleware to validate JSON-RPC requests
const validationMiddleware = [
  body("jsonrpc").equals("2.0"),
  body("method").isString().isLength({ min: 1, max: 100 }),
  body("params").isObject(),
  body("id").optional().isString(),
  (req: Request, res: Response, next: NextFunction) => {
    const tracer = trace.getTracer("middleware");
    const span = tracer.startSpan("middleware.validation", {
      attributes: {
        "request.method": (req as any).method || "unknown",
        "request.url":
          (req as any).originalUrl || (req as any).url || "unknown",
        "validation.type": "json_rpc",
      },
    });

    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        const errorDetails = errors.array();

        span.addEvent("validation.failed", {
          "error.count": errorDetails.length,
          "error.fields": errorDetails
            .map((err) => (err as any).path || (err as any).param || "unknown")
            .join(","),
        });

        span.setAttributes({
          "validation.success": false,
          "validation.error_count": errorDetails.length,
        });

        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: "JSON-RPC validation failed",
        });

        log.warn("JSON-RPC validation failed:", errorDetails);

        return (res as any).status(400).json({
          error: "Validation failed",
          details: errorDetails,
        });
      }

      span.addEvent("validation.success");
      span.setAttributes({
        "validation.success": true,
      });

      span.setStatus({
        code: SpanStatusCode.OK,
        message: "JSON-RPC validation passed",
      });

      next();
    } catch (error) {
      span.addEvent("middleware.validation_error", {
        "error.message": error instanceof Error ? error.message : String(error),
      });
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : String(error),
      });
      throw error;
    } finally {
      span.end();
    }
  },
];

export const securityMiddlewares = [
  authenticateJWT,
  corsMiddleware,
  helmetMiddleware,
  ...jsonMiddleware,
  urlencodedMiddleware,
  ...timeoutMiddleware,
  rateLimiterMiddleware,

  // Optional:
  // ...validationMiddleware,
];
