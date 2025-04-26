import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { Request, Response } from 'express';
import { randomUUID } from 'node:crypto';
import { logger } from './helpers/logs.js';
import { TodoTools } from './tools.js';

const log = logger('server');
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
    log.info('Shutting down server...');
    await this.server.close();
    log.info('Server shutdown complete.');
  }

  async handleGetRequest(req: Request, res: Response) {
    log.info(`GET ${req.originalUrl} (${req.ip})`);
    try {
      log.info('Connecting transport to server...');
      this.transport = new SSEServerTransport('/messages', res);
      this.transports[this.transport.sessionId] = this.transport;

      res.on('close', () => {
        if (this.transport) {
          delete this.transports[this.transport.sessionId];
        }
      });

      await this.server.connect(this.transport);
      log.success('Transport connected. Handling request...');
    } catch (error) {
      log.error('Error handling MCP request:', error);
      if (!res.headersSent) {
        res
          .status(500)
          .json(this.createJSONErrorResponse('Internal server error.'));
        log.error('Responded with 500 Internal Server Error');
      }
    }
  }

  async handlePostRequest(req: Request, res: Response) {
    log.info(`POST ${req.originalUrl} (${req.ip}) - payload:`, req.body);

    const transport = this.transports[req.query.sessionId as string];
    if (transport) {
      const sessionId = req.query.sessionId as string;
      await transport.handlePostMessage(req, res, req.body);
    } else {
      log.error('Transport not initialized. Cannot handle POST request.');
      res
        .status(400)
        .json(
          this.createJSONErrorResponse('No transport found for sessionId.')
        );
    }
  }

  private setupServerRequestHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async (_request) => {
      return {
        tools: TodoTools,
      };
    });
    this.server.setRequestHandler(
      CallToolRequestSchema,
      async (request, _extra) => {
        return {};
      }
    );
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
