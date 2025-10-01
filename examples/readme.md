# Examples

This directory contains examples demonstrating how to integrate and use the MCP Container TypeScript server with various AI platforms and services.

## Prerequisites

Before running the examples, ensure you have:

1. **Node.js** (v23 LTS or new LTS versions) installed
2. **A running MCP server** - Either locally or deployed on Azure Container Apps
3. **OpenAI API key** - Get one from [OpenAI Platform](https://platform.openai.com/api-keys)
4. **MCP server access token** - Generate using the MCP server's authentication system
5. **devtunnel** - If running the MCP server locally and you want to expose it to the internet (for example, to use with Azure OpenAI), you can use a tunneling service like [devtunnel](https://learn.microsoft.com/azure/developer/dev-tunnels/).

## Setup

In order to run the examples, you need to configure the environment variables for the MCP server URL and the JWT token for authentication.

### MCP_SERVER_URL

#### For Azure Deployment
If you already have a deployed MCP server on Azure Container Apps, copy the public URL (e.g., `https://your-app.azurecontainerapps.io`) and set it as the `MCP_SERVER_URL` in your `.env` file. [You can skip to the next section](#mcp_jwt_token)!

#### For Local Development
If you are using a local MCP server with an MCP client provided by a remote provider such as Azure AI Foundry or OpenAI, your local MCP server must be exposed (**temporarily and securely**) to the internet. To achieve this, you will need to install and setup `devtunnel`. Follow the instructions at [devtunnel Quickstart](https://learn.microsoft.com/azure/developer/dev-tunnels/get-started).

Once installed, login to devtunnel using your GitHub account (if you haven't done so already):

```bash
devtunnel user login -g
```

Then start a tunnel to your local MCP server (default port 3000):

```bash
devtunnel host -p 3000
```

Copy the generated public URL (e.g., `https://<your-tunnel-id>.devtunnels.ms:3000`) for use in the `.env` configuration as `MCP_SERVER_URL` (see below).

> [!IMPORTANT]
> The port number must match the port your MCP server is running on (3000 by default).

### MCP_JWT_TOKEN

You will also need an Access Token that is required by the MCP Server. To get a copy of the JWT token for MCP server authentication, either copy the token generated during the MCP server setup (if it's still valid) or generate a new one using the provided script and set it as `MCP_JWT_TOKEN` in your `.env` file.

**From the project root**, run the token generation script:

```bash
npm run generate-token
```

This will output a JWT token in your terminal. Copy the token value to your `/examples/openai/.env` file as `MCP_JWT_TOKEN`.

> [!IMPORTANT]
> Make sure to restart your local MCP server if you regenerate the token, as the server needs to recognize the new token for authentication. If you are using a remote MCP server you deployed on Azure, you will have to redeploy it with the new token (see the [Project README](../README.md#Deploying-the-MCP-Server-to-Azure-Container-Apps) for details).

### Configure the example client

Next, navigate to one of the provided example folders to configure and run a provider-specific example:

```bash
cd examples/openai
```

1. **Install its dependencies:**

```bash
npm install
```

2. **Create environment configuration:**

Copy the sample environment file and configure it:

```bash
cp .env.sample .env
```

3. **Configure environment variables:**

Edit the `.env` file with your credentials and any other necessary configuration, for example:

```bash
# Your OpenAI API key from https://platform.openai.com/api-keys
API_KEY="sk-proj-..."

# The URL of your MCP server
# For Azure deployment: https://your-app.azurecontainerapps.io
# For local development, copy the generated URL from devtunnel: https://<your-tunnel-id>.devtunnels.ms:3000
MCP_SERVER_URL="https://your-app.azurecontainerapps.io"

# JWT token for authenticating with the MCP server
MCP_JWT_TOKEN="your_jwt_token_here"
```

### Running the Example

Once all environment variables are configured, you can run the example:

```bash
npm start
```

### Customizing the Example

You can modify the `index.js` file to test different operations:

#### List all todos (default):

```javascript
const input = `I'd like to see a list of all my todos.`;
```

#### Add a new todo:

```javascript
const input = `Please add a todo: "Learn about MCP"`;
```

#### Complete a todo:

```javascript
const input = `Mark todo #1 as completed.`;
```

#### Delete a todo:

```javascript
const input = `Delete todo #2.`;
```

### Troubleshooting

#### Authentication Errors

```
Error: Unauthorized - Invalid token
```

**Solution:** Regenerate your JWT token using `npm run generate-token` and update `.env`.

#### Connection Errors

```
Error: ECONNREFUSED - Connection refused
```

**Solution:** Ensure your MCP server is running and the `MCP_SERVER_URL` is correct.

#### OpenAI API Errors

```
Error: Incorrect API key provided
```

**Solution:** Verify your `OPENAI_API_KEY` is valid and has sufficient credits.

### Advanced Usage

#### Using Different Models

Modify the `model` parameter in `index.js`:

```javascript
const response = await client.responses.create({
  model: "gpt-5", // or "gpt-4o"
  // ...
});
```

## Additional Examples

More examples will be added to demonstrate:

- Anthropic Claude integration
- Azure OpenAI integration
- Custom MCP client implementations
- Advanced tool composition patterns

## Contributing

To add a new example:

1. Create a new directory under `examples/`
2. Include a `package.json` with dependencies
3. Add a `.env.sample` file for required environment variables
4. Update this README with setup and usage instructions
5. Ensure all examples follow the existing structure and conventions

## Resources

- [Project README](../README.md)
- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [OpenAI API Documentation](https://platform.openai.com/docs)
