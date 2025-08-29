import helmet from "helmet";
import timeout from "connect-timeout";
import cors from "cors";
import { body, validationResult } from "express-validator";
import rateLimit from "express-rate-limit";
import express, { NextFunction, Request, Response } from "express";
import { logger } from "./helpers/logs";
import { authenticateJWT } from "./auth/jwt.js";
const log = logger("middleware");

const loggingMiddleware = (req: Request, res: Response, next: NextFunction) => {
  log.info(`${req.method} ${req.originalUrl} (${req.ip}) - payload:`, req.body || 'NULL');
  
  res.on("finish", () => {
    log.info(`Response sent: ${res.statusCode} ${res.statusMessage}`);
  });
  next();
};

// Middleware to limit the number of requests from a single IP address
const rateLimiterMiddleware = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: "Too many requests from this IP",
    retryAfter: 900, // 15 minutes in seconds
  },
  standardHeaders: true,
  legacyHeaders: false,
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

// Middleware to parse JSON bodies
const jsonMiddleware = express.json({
  limit: "10mb",
  verify: (req, res, buf) => {
    if (buf.length > 10 * 1024 * 1024) {
      throw new Error("Request body too large");
    }
  },
});

// Middleware to parse URL-encoded bodies
const urlencodedMiddleware = express.urlencoded({
  extended: true,
  limit: "10mb",
  parameterLimit: 1000,
});

// Middleware to handle request timeouts
const timeoutMiddleware = [timeout("30s"),
(req: Request, res: Response, next: NextFunction) => {
  if (!req.timedout) next();
}];

// Middleware to validate JSON-RPC requests
const validationMiddleware = [
  body("jsonrpc").equals("2.0"),
  body("method").isString().isLength({ min: 1, max: 100 }),
  body("params").isObject(),
  body("id").optional().isString(),
  (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: "Validation failed",
      details: errors.array(),
    });
  }
  next();
}];

export const securityMiddlewares = [
  loggingMiddleware,
  // authenticateJWT,
  // corsMiddleware,
  // rateLimiterMiddleware,
  // helmetMiddleware,
  // jsonMiddleware,
  // urlencodedMiddleware,
  // ...timeoutMiddleware,
  ...validationMiddleware,
];
