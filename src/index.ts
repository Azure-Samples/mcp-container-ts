import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import express, { Request, Response } from 'express';
import { StreamableHTTPServer } from './server.js';
import { logger } from './helpers/logs.js';
import { hostname } from 'node:os';
const log = logger('index');

const server = new StreamableHTTPServer(
  new Server(
    {
      name: 'todo-http-server',
      version: '1.0.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  )
);

const app = express();
app.use(express.json());

const router = express.Router();
const MCP_ENDPOINT = '/mcp';

router.post(MCP_ENDPOINT, async (req: Request, res: Response) => {
  await server.handlePostRequest(req, res);
});

router.get(MCP_ENDPOINT, async (req: Request, res: Response) => {
  await server.handleGetRequest(req, res);
});

app.use('/', router);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  log.success(`MCP Stateless Streamable HTTP Server`);
  log.success(`MCP endpoint: http://${hostname()}:${PORT}${MCP_ENDPOINT}`);
  log.success(`Press Ctrl+C to stop the server`);
});

process.on('SIGINT', async () => {
  log.error('Shutting down server...');
  await server.close();
  process.exit(0);
});