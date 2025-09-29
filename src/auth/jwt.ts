import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import { trace, SpanStatusCode, context } from "@opentelemetry/api";
import {
  AuthenticatedUser,
  UserRole,
  getUserPermissions,
  Permission,
} from "./authorization.js";
import { logger } from "../helpers/logs.js";

const log = logger("authentication");

export interface JWTPayload {
  id: string;
  email: string;
  role: UserRole;
  permissions?: Permission[];
  iat?: number;
  exp?: number;
  aud?: string | string[];
}

export class JWTService {
  private static readonly SECRET = process.env.JWT_SECRET;
  private static readonly AUDIENCE = process.env.JWT_AUDIENCE || "urn:bar";
  private static readonly ISSUER = process.env.JWT_ISSUER || "urn:foo";
  static verifyToken(token: string): AuthenticatedUser {
    if (!this.SECRET) {
      throw new Error("JWT_SECRET environment variable is required");
    }

    try {
      const {payload} = jwt.verify(token, Buffer.from(this.SECRET, "utf-8"), {
        iss: this.ISSUER,
        aud: this.AUDIENCE,
        algorithm: "HS256",
        complete: true,
      } as any) as { payload: jwt.JwtPayload };

      return {
        id: payload.id,
        email: payload.email,
        role: payload.role,
        permissions: payload.permissions,
        iat: payload.iat,
        exp: payload.exp,
      };
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error("Token expired");
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new Error("Invalid token: " + error.message);
      } else {
        throw new Error("Token verification failed");
      }
    }
  }
}

export function authenticateJWT(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const tracer = trace.getTracer("mcp-server");
  const rootSpan = tracer.startSpan("auth.authenticateJWT", {
    attributes: {
      httpRoute: req.originalUrl || req.url,
      httpMethod: req.method,
      ip: req.ip,
    },
  });
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    log.warn("Authentication failed: No token provided", { ip: req.ip });
    rootSpan.addEvent("auth.missingToken");
    rootSpan.setStatus({ code: SpanStatusCode.ERROR, message: "No token" });
    rootSpan.end();
    res.status(401).json({
      error: "Authentication required",
      message: "Bearer token must be provided in Authorization header",
    });
    return;
  }

  try {
    const verifySpan = tracer.startSpan("auth.jwt.verify", {
      attributes: {
        tokenLength: token.length,
      },
    }, trace.setSpan(context.active(), rootSpan));
    const user = JWTService.verifyToken(token);
    verifySpan.setAttribute("user.id", user.id);
    verifySpan.setAttribute("user.role", user.role);
    verifySpan.end();

    // Check if token is about to expire (within 5 minutes)
    const now = Math.floor(Date.now() / 1000);
    const timeToExpiry = (user.exp || 0) - now;

    if (timeToExpiry < 300) {
      // 5 minutes
      log.warn(`Token expiring soon for user ${user.id}`, { timeToExpiry });
      rootSpan.addEvent("auth.tokenExpiringSoon", { userId: user.id, timeToExpiry });
    }

    (req as any).user = user;
    log.info(`User authenticated: ${user.id} (${user.role})`);
    rootSpan.setAttribute("auth.user.id", user.id);
    rootSpan.setAttribute("auth.user.role", user.role);
    rootSpan.setStatus({ code: SpanStatusCode.OK });
    rootSpan.end();
    next();
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Unknown error";
    log.warn("Authentication failed:", errorMessage, { ip: req.ip });
    rootSpan.recordException(error as Error);
    rootSpan.setStatus({ code: SpanStatusCode.ERROR, message: errorMessage });
    rootSpan.end();
    res.status(403).json({
      error: "Invalid token",
      message: errorMessage,
    });
  }
}

// Optional: API Key authentication for service-to-service communication
export function authenticateAPIKey(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const tracer = trace.getTracer('authentication');
  const span = tracer.startSpan('auth.authenticateAPIKey', {
    attributes: {
      'auth.method': 'api_key',
      'request.method': (req as any).method || 'unknown',
      'request.url': (req as any).originalUrl || (req as any).url || 'unknown',
      'request.ip': (req as any).ip || 'unknown',
    },
  });
  
  try {
    const apiKey = req.headers["x-api-key"] as string;
    const validAPIKeys = process.env.API_KEYS?.split(",") || [];
    
    span.setAttributes({
      'api_key.provided': !!apiKey,
      'api_key.length': apiKey?.length || 0,
      'api_key.valid_keys_count': validAPIKeys.length,
    });
    
    if (!apiKey) {
      span.addEvent('auth.api_key_missing');
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: 'API key not provided',
      });
      log.warn("API Key authentication failed: No API key provided", { ip: (req as any).ip });
      (res as any).status(401).json({ error: "Invalid API key" });
      return;
    }
    
    if (!validAPIKeys.includes(apiKey)) {
      span.addEvent('auth.api_key_invalid', {
        'api_key.length': apiKey.length,
      });
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: 'Invalid API key',
      });
      log.warn("API Key authentication failed: Invalid key", { ip: (req as any).ip });
      (res as any).status(401).json({ error: "Invalid API key" });
      return;
    }

    // For API key auth, create a service user
    const serviceUser = {
      id: "service",
      email: "service@internal",
      role: UserRole.ADMIN,
      permissions: getUserPermissions(UserRole.ADMIN),
    };
    
    (req as any).user = serviceUser;
    
    span.setAttributes({
      'user.id': serviceUser.id,
      'user.role': serviceUser.role,
      'user.permissions_count': serviceUser.permissions.length,
      'auth.success': true,
    });
    
    span.addEvent('auth.api_key_authenticated', {
      'user.id': serviceUser.id,
      'user.role': serviceUser.role,
    });
    
    span.setStatus({
      code: SpanStatusCode.OK,
      message: 'API key authentication successful',
    });

    log.info("Service authenticated via API key");
    next();
  } catch (error) {
    span.addEvent('auth.api_key_error', {
      'error.message': error instanceof Error ? error.message : String(error),
    });
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    log.error('API key authentication error:', error);
    (res as any).status(500).json({ error: 'Internal authentication error' });
  } finally {
    span.end();
  }
}

// Middleware to allow either JWT or API key authentication
export function authenticateAny(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const tracer = trace.getTracer('authentication');
  const span = tracer.startSpan('auth.authenticateAny', {
    attributes: {
      'request.method': (req as any).method || 'unknown',
      'request.url': (req as any).originalUrl || (req as any).url || 'unknown',
      'request.ip': (req as any).ip || 'unknown',
    },
  });
  
  try {
    const hasJWT = req.headers.authorization?.startsWith("Bearer ");
    const hasAPIKey = req.headers["x-api-key"];
    
    span.setAttributes({
      'auth.has_jwt': hasJWT,
      'auth.has_api_key': !!hasAPIKey,
      'auth.methods_available': [hasJWT && 'jwt', hasAPIKey && 'api_key'].filter(Boolean).join(','),
    });

    if (hasJWT) {
      span.addEvent('auth.using_jwt');
      span.setAttributes({
        'auth.method_chosen': 'jwt',
      });
      authenticateJWT(req, res, next);
    } else if (hasAPIKey) {
      span.addEvent('auth.using_api_key');
      span.setAttributes({
        'auth.method_chosen': 'api_key',
      });
      authenticateAPIKey(req, res, next);
    } else {
      span.addEvent('auth.no_method_provided');
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: 'No authentication method provided',
      });
      log.warn("No authentication method provided", { ip: (req as any).ip });
      (res as any).status(401).json({
        error: "Authentication required",
        message: "Provide either Bearer token or X-API-Key header",
      });
      return;
    }
    
    span.setStatus({
      code: SpanStatusCode.OK,
      message: 'Authentication method selected',
    });
  } catch (error) {
    span.addEvent('auth.any_method_error', {
      'error.message': error instanceof Error ? error.message : String(error),
    });
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  } finally {
    span.end();
  }
}
