# Building Your First MCP Server and Deploying to Azure Container Apps

The Model Context Protocol (MCP) is an open standard that enables AI models and tools to communicate seamlessly. This guide walks you through building a TypeScript-based MCP server that can run locally or on Azure Container Apps, providing a foundation for AI-powered applications.

## What is MCP?

MCP acts as a bridge between AI models and various tools or services. It provides a standardized way for AI systems to interact with external resources, databases, APIs, and custom business logic. Think of it as a protocol that allows your AI assistant to perform actions beyond just generating text.

## Architecture Overview

Our MCP server consists of:

- **HTTP Server**: Handles incoming requests from MCP clients
- **Tool Registry**: Defines available actions the AI can perform
- **Database Layer**: Manages persistent state using SQLite
- **Transport Layer**: Handles communication via HTTP or Server-Sent Events

## Project Setup

First, let's set up the project structure:

```bash
mkdir mcp-todo-server
cd mcp-todo-server
npm init -y
```

Install the required dependencies:

```bash
npm install @modelcontextprotocol/sdk better-sqlite3 express debug chalk
npm install -D @types/express @types/better-sqlite3 @types/debug @types/node tsx typescript
```

Create a `tsconfig.json` file:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "node",
    "outDir": "./build",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules"]
}
```

Update your `package.json` to include ES modules and scripts:

```json
{
  "type": "module",
  "scripts": {
    "start": "tsx src/index.ts",
    "dev": "tsx watch src/index.ts",
    "build": "tsc"
  }
}
```

## Database Layer

Create `src/db.ts` to handle our SQLite database operations:

```typescript
import Database from "better-sqlite3";

const db = new Database(":memory:");

// Initialize the database
db.pragma("journal_mode = WAL");
db.prepare(`
  CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0
  )
`).run();

export async function addTodo(text: string) {
  const stmt = db.prepare("INSERT INTO todos (text, completed) VALUES (?, 0)");
  return stmt.run(text);
}

export async function listTodos() {
  const todos = db.prepare("SELECT id, text, completed FROM todos").all() as Array<{
    id: number;
    text: string;
    completed: number;
  }>;
  return todos.map(todo => ({
    ...todo,
    completed: Boolean(todo.completed)
  }));
}

export async function completeTodo(id: number) {
  const stmt = db.prepare("UPDATE todos SET completed = 1 WHERE id = ?");
  return stmt.run(id);
}

export async function deleteTodo(id: number) {
  const row = db.prepare("SELECT text FROM todos WHERE id = ?").get(id) as 
    { text: string } | undefined;
  if (!row) return null;
  
  db.prepare("DELETE FROM todos WHERE id = ?").run(id);
  return row;
}
```

## Tool Definitions

Create `src/tools.ts` to define the available MCP tools:

```typescript
import { addTodo, listTodos, completeTodo, deleteTodo } from "./db.js";

export const TodoTools = [
  {
    name: "add_todo",
    description: "Add a new TODO item to the list",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string" }
      },
      required: ["title"]
    },
    outputSchema: {
      type: "object",
      properties: {
        content: {
          type: "array",
          items: { type: "string" }
        }
      },
      required: ["content"]
    },
    async execute({ title }: { title: string }) {
      const info = await addTodo(title);
      return {
        content: [`Added TODO: ${title} (id: ${info.lastInsertRowid})`]
      };
    }
  },
  {
    name: "list_todos",
    description: "List all TODO items",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    },
    outputSchema: {
      type: "object",
      properties: {
        content: {
          type: "array",
          items: { type: "string" }
        }
      },
      required: ["content"]
    },
    async execute() {
      const todos = await listTodos();
      if (!todos || todos.length === 0) {
        return { content: ["No TODOs found."] };
      }
      return {
        content: todos.map(
          (t) => `${t.text} (id: ${t.id})${t.completed ? " [completed]" : ""}`
        )
      };
    }
  },
  {
    name: "complete_todo",
    description: "Mark a TODO item as completed",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number" }
      },
      required: ["id"]
    },
    outputSchema: {
      type: "object",
      properties: {
        content: {
          type: "array",
          items: { type: "string" }
        }
      },
      required: ["content"]
    },
    async execute({ id }: { id: number }) {
      const info = await completeTodo(id);
      if (info.changes === 0) {
        return { content: [`TODO with id ${id} not found.`] };
      }
      return { content: [`TODO with id ${id} marked as completed.`] };
    }
  }
];
```

## MCP Server Implementation

Create `src/server.ts` for the main MCP server logic:

```typescript
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { Request, Response } from 'express';
import { TodoTools } from './tools.js';

export class StreamableHTTPServer {
  server: Server;

  constructor(server: Server) {
    this.server = server;
    this.setupServerRequestHandlers();
  }

  async handlePostRequest(req: Request, res: Response) {
    try {
      const transport = new StreamableHTTPServerTransport();
      await this.server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error('Error handling MCP request:', error);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Internal server error' });
      }
    }
  }

  private setupServerRequestHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return { tools: TodoTools };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      const tool = TodoTools.find(tool => tool.name === name);

      if (!tool) {
        throw new Error(`Tool ${name} not found`);
      }

      const result = await tool.execute(args as any);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result)
          }
        ]
      };
    });
  }
}
```

## HTTP Server Setup

Create `src/index.ts` as the main entry point:

```typescript
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import express from 'express';
import { StreamableHTTPServer } from './server.js';

const mcpServer = new StreamableHTTPServer(
  new Server(
    {
      name: 'todo-http-server',
      version: '1.0.0'
    },
    {
      capabilities: {
        tools: {}
      }
    }
  )
);

const app = express();
app.use(express.json());

app.post('/mcp', async (req, res) => {
  await mcpServer.handlePostRequest(req, res);
});

app.get('/mcp', (req, res) => {
  res.status(405).json({ error: 'Method not allowed' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`MCP Server running on port ${PORT}`);
  console.log(`Endpoint: http://localhost:${PORT}/mcp`);
});
```

## Local Development and Testing

Start your MCP server locally:

```bash
npm run dev
```

Test the server using curl:

```bash
# List available tools
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}'

# Add a todo
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "add_todo",
      "arguments": {"title": "Buy groceries"}
    }
  }'
```

## Azure Container Apps Deployment

### Prerequisites

Install the Azure CLI and Azure Developer CLI:

```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Install Azure Developer CLI
curl -fsSL https://aka.ms/install-azd.sh | bash
```

### Infrastructure as Code

Create `azure.yaml` for Azure Developer CLI:

```yaml
name: mcp-container-ts
services:
  mcp-container-ts:
    project: .
    host: containerapp
    language: ts
    docker:
      path: Dockerfile
```

Create `Dockerfile` for containerization:

```dockerfile
FROM node:22-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-slim AS production
WORKDIR /app
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/build ./build
RUN npm ci --omit=dev && npm cache clean --force
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
USER appuser
CMD ["node", "./build/index.js"]
```

### Bicep Infrastructure

Create `infra/main.bicep`:

```bicep
targetScope = 'subscription'

@description('Name of the environment')
param environmentName string

@description('Primary location for all resources')
param location string

var tags = {
  'azd-env-name': environmentName
}

resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: 'rg-${environmentName}'
  location: location
  tags: tags
}

module resources 'resources.bicep' = {
  scope: rg
  name: 'resources'
  params: {
    location: location
    tags: tags
  }
}

output AZURE_CONTAINER_REGISTRY_ENDPOINT string = resources.outputs.AZURE_CONTAINER_REGISTRY_ENDPOINT
```

Create `infra/resources.bicep`:

```bicep
@description('The location used for all deployed resources')
param location string = resourceGroup().location

@description('Tags that will be applied to all resources')
param tags object = {}

var resourceToken = uniqueString(subscription().id, resourceGroup().id, location)

// Container registry
module containerRegistry 'br/public:avm/res/container-registry/registry:0.1.1' = {
  name: 'registry'
  params: {
    name: 'cr${resourceToken}'
    location: location
    tags: tags
    publicNetworkAccess: 'Enabled'
  }
}

// Container apps environment
module containerAppsEnvironment 'br/public:avm/res/app/managed-environment:0.4.5' = {
  name: 'container-apps-environment'
  params: {
    name: 'cae-${resourceToken}'
    location: location
    zoneRedundant: false
  }
}

// Container app
module containerApp 'br/public:avm/res/app/container-app:0.8.0' = {
  name: 'mcp-container-ts'
  params: {
    name: 'mcp-container-ts'
    ingressTargetPort: 3000
    containers: [
      {
        image: 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest'
        name: 'main'
        resources: {
          cpu: json('0.5')
          memory: '1.0Gi'
        }
        env: [
          {
            name: 'PORT'
            value: '3000'
          }
        ]
      }
    ]
    environmentResourceId: containerAppsEnvironment.outputs.resourceId
    location: location
    tags: tags
  }
}

output AZURE_CONTAINER_REGISTRY_ENDPOINT string = containerRegistry.outputs.loginServer
```

### Deployment Commands

Deploy to Azure:

```bash
# Login to Azure
az login

# Initialize the Azure Developer CLI project
azd init

# Deploy infrastructure and application
azd up
```

Monitor the deployment:

```bash
# Check deployment status
azd show

# View logs
az containerapp logs show --name mcp-container-ts --resource-group rg-<your-environment>
```

## Testing Your Deployed MCP Server

Once deployed, test your Azure-hosted MCP server:

```bash
# Replace with your actual Container Apps URL
AZURE_URL="https://mcp-container-ts.example.azurecontainerapps.io"

# Test the deployed server
curl -X POST ${AZURE_URL}/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}'
```

## Integration with VS Code

Create `.vscode/mcp.json` for VS Code integration:

```json
{
  "servers": {
    "mcp-server-local": {
      "type": "http",
      "url": "http://localhost:3000/mcp"
    },
    "mcp-server-azure": {
      "type": "http",
      "url": "https://your-app.azurecontainerapps.io/mcp"
    }
  }
}
```

## Best Practices

1. **Error Handling**: Always implement proper error handling in your tools
2. **Authentication**: Add authentication for production deployments
3. **Logging**: Implement structured logging for debugging
4. **Monitoring**: Set up Application Insights for production monitoring
5. **Resource Management**: Use appropriate CPU and memory limits
6. **Security**: Run containers as non-root users

## Scaling and Performance

Azure Container Apps automatically scales based on demand:

```bicep
// In your container app resource
scaleMinReplicas: 1
scaleMaxReplicas: 10
```

For high-performance scenarios, consider:

- Using persistent storage instead of in-memory SQLite
- Implementing connection pooling
- Adding caching layers
- Using Azure Database for PostgreSQL for production workloads

## Cleanup

To avoid charges, clean up your resources:

```bash
# Remove all deployed resources
azd down --purge --force
```

## Conclusion

You've successfully built and deployed an MCP server to Azure Container Apps. This foundation provides a scalable, serverless platform for AI-powered applications. The server can be extended with additional tools, integrated with various Azure services, and scaled to handle production workloads.

The MCP protocol opens up possibilities for creating sophisticated AI agents that can interact with your business systems, databases, and APIs in a standardized way. Consider exploring additional integrations such as Azure Cognitive Services, Azure Storage, or custom business logic to enhance your MCP server's capabilities.
