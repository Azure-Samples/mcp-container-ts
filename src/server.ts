import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  JSONRPCError,
  JSONRPCNotification,
  ListToolsRequestSchema,
  LoggingMessageNotification,
  Notification,
  SetLevelRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { context, ContextAPI, Span, SpanStatusCode, trace, TraceAPI } from "@opentelemetry/api";
import { Request, Response } from "express";
import { randomUUID } from "node:crypto";
import {
  AuthenticatedUser,
  hasPermission,
  Permission,
} from "./auth/authorization.js";
import { logger } from "./helpers/logs.js";
import { TodoTools } from "./tools.js";

const log = logger("server");
const JSON_RPC = "2.0";
const JSON_RPC_ERROR = -32603;

export class StreamableHTTPServer {
  server: Server;
  private currentUser: AuthenticatedUser | null = null;

  constructor() {
    this.server = new Server(
      {
        name: "todo-http-server",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
          logging: {
            level: "info",
          },
        },
      }
    );
    this.setupServerRequestHandlers();
  }

  private getToolRequiredPermissions(toolName: string): Permission[] {
    const toolPermissions: Record<string, Permission[]> = {
      add_todo: [Permission.CREATE_TODOS],
      list_todos: [Permission.READ_TODOS],
      complete_todo: [Permission.UPDATE_TODOS],
      delete_todo: [Permission.DELETE_TODOS],
      updateTodoText: [Permission.UPDATE_TODOS],
    };

    return toolPermissions[toolName] || [];
  }

  async close() {
    const tracer = trace.getTracer("mcp-server");
    const span = tracer.startSpan("server.close");
    
    try {
      log.info("Closing MCP server...");
      
      span.addEvent("server.closing_started");
      
      const closeStart = Date.now();
      await this.server.close();
      const closeTime = Date.now() - closeStart;
      
      span.setAttributes({
        "server.close_time_ms": closeTime,
        "server.close_success": true,
      });
      
      span.addEvent("server.closed_successfully", {
        "close_time_ms": closeTime,
      });
      
      span.setStatus({
        code: SpanStatusCode.OK,
        message: "Server closed successfully",
      });
      
      log.success("MCP server closed successfully");
    } catch (error) {
      span.addEvent("server.close_error", {
        "error.message": error instanceof Error ? error.message : String(error),
      });
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : String(error),
      });
      log.error("Error closing MCP server:", error);
      throw error;
    } finally {
      span.end();
    }
  }

  async handleStreamableHTTP(req: Request, res: Response) {
    log.info(
      `${req.method} ${req.originalUrl} (${req.ip}) - payload:`,
      req.body || "{}"
    );

    // Extract user from request (set by authentication middleware)
    this.currentUser = (req as any).user as AuthenticatedUser;

    try {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });

      log.info("Connecting transport to server...");

      await this.server.connect(transport);
      log.success("Transport connected. Handling request...");

      await transport.handleRequest(req, res, req.body);
      res.on("close", () => {
        log.success("Request closed by client");
        transport.close();
        this.server.close();
        this.currentUser = null; // Clear user after request
      });

      await this.sendMessages();
      log.success(
        `${req.method} request handled successfully (status=${res.statusCode})`
      );
    } catch (error) {
      log.error("Error handling MCP request:", error);
      if (!res.headersSent) {
        res
          .status(500)
          .json(this.createRPCErrorResponse("Internal server error."));
        log.error("Responded with 500 Internal Server Error");
      }
    }
  }

  private listTools(parentSpan: Span, trace: TraceAPI, context: ContextAPI) {
    const ctx = trace.setSpan(context.active(), parentSpan);
    const tracer = trace.getTracer("mcp-server");
    const span = tracer.startSpan("listTools", undefined, ctx);

    const user = this.currentUser;
    span.setAttribute("user.id", user?.id || "anonymous");
    span.setAttribute("user.role", user?.role || "none");

    // Check if user has permission to list tools
    if (!user || !hasPermission(user, Permission.LIST_TOOLS)) {
      log.warn(`User ${user?.id || "unknown"} denied permission to list tools`);
      span.addEvent("authorization.denied", { reason: "missing LIST_TOOLS" });
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: "Permission denied",
      });
      const resp = this.createRPCErrorResponse(
        "Insufficient permissions to list tools"
      );
      span.end();
      return resp;
    }

    // Filter tools based on user permissions
    const filterSpan = tracer.startSpan("authorization.filterTools");
    const allowedTools = TodoTools.filter((tool) => {
      const requiredPermissions = this.getToolRequiredPermissions(tool.name);
      const allowed = requiredPermissions.some((permission: Permission) =>
        hasPermission(user, permission)
      );
      if (allowed) {
        filterSpan.addEvent("tool.allowed", { tool: tool.name });
      } else {
        filterSpan.addEvent("tool.denied", { tool: tool.name });
      }
      return allowed;
    });
    filterSpan.setAttribute("tools.allowed.count", allowedTools.length);
    filterSpan.end();

    log.info(`User ${user.id} listed ${allowedTools.length} available tools`);
    span.setAttribute("tools.returned", allowedTools.length);
    span.setStatus({ code: SpanStatusCode.OK });
    span.end();
    return {
      jsonrpc: JSON_RPC,
      tools: allowedTools,
    };
  }

  private setupServerRequestHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async (request) => {
      const tracer = trace.getTracer("mcp-server");
      const parentSpan = tracer.startSpan("main");
      return this.listTools(parentSpan, trace, context);
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const tracer = trace.getTracer("mcp-server");
      const span = tracer.startSpan("callTool", {
        attributes: {
          "tool.name": request.params.name,
          "tool.arguments": JSON.stringify(request.params.arguments),
        },
      });

      const args = request.params.arguments;
      const toolName = request.params.name;
      const user = this.currentUser;
      const tool = TodoTools.find((tool) => tool.name === toolName);

      // Add user context to span
      if (user) {
        span.setAttributes({
          "user.id": user.id,
          "user.role": user.role,
          "user.email": user.email || "unknown",
        });
      }

      log.info(
        `User ${user?.id || "unknown"} attempting to call tool: ${toolName}`
      );

      try {
        if (!user) {
          span.addEvent("authentication.failed", {
            reason: "no_user_context",
          });
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: "Authentication required",
          });
          log.warn(`Unauthenticated user attempted to call tool: ${toolName}`);
          return this.createRPCErrorResponse("Authentication required");
        }

        if (!tool) {
          span.addEvent("tool.not_found", {
            "tool.name": toolName,
          });
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: "Tool not found",
          });
          log.error(`Tool ${toolName} not found.`);
          return this.createRPCErrorResponse(`Tool ${toolName} not found.`);
        }

        // Check tool-specific permissions
        const requiredPermissions = this.getToolRequiredPermissions(toolName);
        const hasRequiredPermission = requiredPermissions.some(
          (permission: Permission) => hasPermission(user, permission)
        );

        span.setAttributes({
          "authorization.required_permissions": requiredPermissions.join(","),
          "authorization.has_permission": hasRequiredPermission,
        });

        if (!hasRequiredPermission) {
          span.addEvent("authorization.denied", {
            "user.id": user.id,
            "tool.name": toolName,
            "required_permissions": requiredPermissions.join(","),
          });
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: "Insufficient permissions",
          });
          log.warn(`User ${user.id} denied permission to call tool: ${toolName}`);
          return this.createRPCErrorResponse(
            `Insufficient permissions to call tool: ${toolName}`
          );
        }

        log.info(`Executing tool ${toolName} with arguments:`, args);
        span.addEvent("tool.execution_started", {
          "tool.name": toolName,
          "arguments.count": args ? Object.keys(args).length : 0,
        });

        const executionStart = Date.now();
        const result = await tool.execute(args as any);
        const executionTime = Date.now() - executionStart;

        span.setAttributes({
          "tool.execution_time_ms": executionTime,
          "tool.result_type": typeof result,
        });

        span.addEvent("tool.execution_completed", {
          "execution_time_ms": executionTime,
          "result_content_items": result.content?.length || 0,
        });

        span.setStatus({
          code: SpanStatusCode.OK,
          message: "Tool executed successfully",
        });

        log.success(
          `User ${user.id} successfully executed tool ${toolName}. Result:`,
          result
        );
        return {
          jsonrpc: JSON_RPC,
          ...result,
        };
      } catch (error) {
        span.addEvent("tool.execution_error", {
          "error.message": error instanceof Error ? error.message : String(error),
          "error.name": error instanceof Error ? error.name : "unknown",
        });
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: error instanceof Error ? error.message : String(error),
        });
        log.error(
          `Error executing tool ${toolName} for user ${user?.id || "unknown"}:`,
          error
        );
        return this.createRPCErrorResponse(
          `Error executing tool ${toolName}: ${error}`
        );
      } finally {
        span.end();
      }
    });

    this.server.setRequestHandler(SetLevelRequestSchema, async (request) => {
      const { level } = request.params;
      log.info(`Setting log level to: ${level}`);

      // Demonstrate different log levels
      await this.server.notification({
        method: "notifications/message",
        params: {
          level: "debug",
          logger: "test-server",
          data: `Logging level set to: ${level}`,
        },
      });

      return {};
    });
  }

  private async sendMessages() {
    const tracer = trace.getTracer("mcp-server");
    const span = tracer.startSpan("server.sendMessages");
    
    try {
      const message: LoggingMessageNotification = {
        method: "notifications/message",
        params: { level: "info", data: "Connection established" },
      };
      
      span.addEvent("message.created", {
        "message.method": message.method,
        "message.level": message.params.level,
      });
      
      log.info("Sending connection established notification.");
      await this.sendNotification(message);
      
      span.addEvent("message.sent_successfully");
      span.setStatus({
        code: SpanStatusCode.OK,
        message: "Messages sent successfully",
      });
    } catch (error) {
      span.addEvent("message.send_error", {
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
  }

  private async sendNotification(notification: Notification) {
    const tracer = trace.getTracer("mcp-server");
    const span = tracer.startSpan("server.sendNotification", {
      attributes: {
        "notification.method": notification.method,
      },
    });
    
    try {
      const rpcNotificaiton: JSONRPCNotification = {
        ...notification,
        jsonrpc: JSON_RPC,
      };
      
      span.setAttributes({
        "rpc.jsonrpc_version": JSON_RPC,
        "rpc.method": notification.method,
      });
      
      span.addEvent("notification.sending", {
        "method": notification.method,
      });
      
      log.info(`Sending notification: ${notification.method}`);
      const startTime = Date.now();
      await this.server.notification(rpcNotificaiton);
      const sendTime = Date.now() - startTime;
      
      span.setAttributes({
        "notification.send_time_ms": sendTime,
      });
      
      span.addEvent("notification.sent", {
        "method": notification.method,
        "send_time_ms": sendTime,
      });
      
      span.setStatus({
        code: SpanStatusCode.OK,
        message: "Notification sent successfully",
      });
    } catch (error) {
      span.addEvent("notification.send_error", {
        "error.message": error instanceof Error ? error.message : String(error),
        "notification.method": notification.method,
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

  private createRPCErrorResponse(message: string): JSONRPCError {
    return {
      jsonrpc: JSON_RPC,
      error: {
        code: JSON_RPC_ERROR,
        message: message,
      },
      id: randomUUID(),
    };
  }
}
