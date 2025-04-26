import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { Request, Response } from "express";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { TransportsCache } from "./helpers/cache.js";
import { logger } from "./helpers/logs.js";
import { TodoTools } from "./tools.js";

const log = logger("server");
const JSON_ERROR = 500;

export class SSEPServer {
  server: Server;
  transport: SSEServerTransport | null = null;
  transports: Record<string, SSEServerTransport> = {};

  constructor(server: Server) {
    this.server = server;
    this.setupServerRequestHandlers();
  }

  async close() {
    log.info("Shutting down server...");
    await this.server.close();
    log.info("Server shutdown complete.");
  }

  async handleGetRequest(req: Request, res: Response) {
    log.info(`GET ${req.originalUrl} (${req.ip})`);
    try {
      log.info("Connecting transport to server...");
      this.transport = new SSEServerTransport("/messages", res);
      TransportsCache.set(this.transport.sessionId, this.transport);

      res.on("close", () => {
        if (this.transport) {
          TransportsCache.delete(this.transport.sessionId);
        }
      });

      await this.server.connect(this.transport);
      log.success("Transport connected. Handling request...");
    } catch (error) {
      log.error("Error handling MCP request:", error);
      if (!res.headersSent) {
        res
          .status(500)
          .json(this.createJSONErrorResponse("Internal server error."));
        log.error("Responded with 500 Internal Server Error");
      }
    }
  }

  async handlePostRequest(req: Request, res: Response) {
    log.info(`POST ${req.originalUrl} (${req.ip}) - payload:`, req.body);

    const sessionId = req.query.sessionId as string;
    const transport = TransportsCache.get(sessionId);
    if (transport) {
      await transport.handlePostMessage(req, res, req.body);
    } else {
      log.error("Transport not initialized. Cannot handle POST request.");
      res
        .status(400)
        .json(
          this.createJSONErrorResponse(
            "No transport found for sessionId=" + sessionId
          )
        );
    }
  }

  private setupServerRequestHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async (_request) => {
      return {
        tools: TodoTools,
      };
    });
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const tool = TodoTools.find((tool) => tool.name === name);
        if (!tool) {
          log.error(`Tool "${name}" not found.`);
          return this.createJSONErrorResponse(`Tool "${name}" not found.`);
        }

        const response = await tool.execute(args as any);

        return { content: [{ type: "text", text: response }] };
      } catch (error) {
        if (error instanceof z.ZodError) {
          throw new Error(
            `Invalid arguments: ${error.errors
              .map((e) => `${e.path.join(".")}: ${e.message}`)
              .join(", ")}`
          );
        }
        throw error;
      }
    });
  }

  private createJSONErrorResponse(message: string) {
    return {
      error: {
        code: JSON_ERROR,
        message: message,
      },
      id: randomUUID(),
    };
  }
}
