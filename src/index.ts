import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import express, { Request, Response } from 'express';
import { logger } from './helpers/logs.js';
import { SSEPServer } from './server.js';

const log = logger('index');

const server = new SSEPServer(
  new Server(
    {
      name: 'todo-sse-server',
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

// Legacy message endpoint for older clients
router.post('/messages', async (req: Request, res: Response) => {
  await server.handlePostRequest(req, res);
});

// Legacy SSE endpoint for older clients
router.get('/sse', async (req: Request, res: Response) => {
  await server.handleGetRequest(req, res);
});

app.use('/', router);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  log.success(`MCP SSE Server`);
  log.success(`MCP SSE endpoint: http://localhost:${PORT}/sse`);
  log.success(`Press Ctrl+C to stop the server`);
});

process.on('SIGINT', async () => {
  log.error('Shutting down server...');
  await server.close();
  process.exit(0);
});
