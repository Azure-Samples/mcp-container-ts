<!--
---
name: Remote MCP with Azure Container Apps (Node.js/TypeScript/JavaScript)
description: Run a remote MCP server on Azure Container Apps.  
languages:
- typescript
- javascript
- nodejs
- bicep
- azdeveloper
products:
- container-apps
- azure
page_type: sample
urlFragment: mcp-container-ts
---
-->
# Getting Started with Remote MCP Servers using Azure Container Apps (Node.js/TypeScript)

<p align="center">
  <img src="./docs/ghcp-mcp-in-action.png" width="600" alt="MCP and GHCP in Action" />
</p>

This is a quick start guide to help you set up a remote MCP server using Azure Container Apps with Node.js and TypeScript. The guide assumes you have basic knowledge of Azure, Docker, and Node.js.

Below is the architecture diagram for a typical MCP server setup:


```mermaid
flowchart TD
    User[User]
    Host["VS Code, GHCP..."]
    ClientSSE[MCP Client]
    ServerSSE[MCP Server]
    Tools[Tools]
    LLM[Azure OpenAI / OpenAI / GitHub Models]
    Postgres[(PostgreSQL)]

    User --> host 
    subgraph host["MCP Host"]
        Host -.-> ClientSSE
        Host <-.-> |LLM Provider| LLM
    end
    ClientSSE a@---> |"SSE Endpoint /sse"| server
    a@{ animate: true }

    subgraph server["ACA Container"]
        ServerSSE -.- Tools
    end
    style server fill:#9B77E8,color:#fff,stroke:#5EB4D8,stroke-width:2px
    
    subgraph db["ACA Container"]
        Tools b@--> |CRUD| Postgres
        b@{ animate: true }
    end
    style db fill:#9B77E8,color:#fff,stroke:#5EB4D8,stroke-width:2px

```

## Getting Started

To get started with this project, follow the steps below:

## Prerequisites

- Node.js (version 23 or higher) and npm 
- Docker (recommended for running the MCP servers, and Postgres in Docker)

## Prepare your local environment

A Postgres database is needed to store the TODO items. You can run Postgres in a Docker container or use an existing Postgres database. If you want to run it in a Docker container, you can use the following command:

```bash
docker compose up -d --build 'postgres'                                                                 
```

This will create a Docker container with Postgres running on port 5432. The MCP server will connect to this database to store the TODO items.
You should see the following output:

```bash
[+] Running 2/2
 ✔ Network mcp-container-ts_default        Created             0.0s 
 ✔ Container mcp-container-ts-postgres-1   Started             0.2s    
```

## Run your MCP Server locally from the terminal

1. Clone this repository.
2. Install dependencies

```bash
npm install
```

3. Start the server

```bash
npm start
```

## Use the local MCP server from within a host

### Option 1 - Use the mcp.json file

You can use the provided [mcp.json](.vscode/mcp.json) configuration file to set up the MCP server in your VS Code environment. This configuration file contains the necessary settings for the MCP server, including the URL and transport type.
```json
{
  "servers": {
    "mcp-server-sse": {
      "type": "sse",
      "url": "http://localhost:3000/sse"
    }
  }
}
```

Once you have this file open, you can click on the "start" button that will connect the MCP server and fetch the available tools. You can also see the logs output in the terminal from the MCP server.


### Option 2 - Manually Adding MCP Server to your host

1. Add MCP Server from command palette and add URL to your running Function app's SSE endpoint:

```bash
http://localhost:3000/sse
```

2. Select HTTP (Server-Sent-Events) for the type of MCP server to add.
3. Enter the URL to your running function app's SSE endpoint
4. Enter the server ID. (This can be any name you want)
5. Choose if you want to run this in your User settings (available to all apps for you) or to your Workspace settings (available to this app, only)
6. In Copilot chat agent mode enter a prompt to trigger the tool, e.g., select some code and enter this prompt

```bash
Add water to my grocery list
```
7. When prompted to run the tool, consent by clicking Continue
8. When you're done, press Ctrl+C in the terminal window to stop the func.exe host process, and List MCP Servers from command palette and stop the local server.


### Option 3 - MCP Inspector

1. In a new terminal window, install and run MCP Inspector

```bash
npx -y @modelcontextprotocol/inspector@latest node build/index.js
```

2. CTRL click to load the MCP Inspector web app from the URL displayed by the app (e.g. http://0.0.0.0:5173/#resources)
3. Set the transport type to SSE
4. Set the URL to your running Function app's SSE endpoint and Connect:
```bash
http://localhost:3000/sse
```
5. List Tools. Click on a tool and Run Tool.

## Deploy to Azure for Remote MCP

TODO

## Next Steps

- Learn more about related MCP efforts from Microsoft