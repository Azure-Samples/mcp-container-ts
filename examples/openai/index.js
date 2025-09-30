import "dotenv/config";
import OpenAI from "openai";

const client = new OpenAI({
  logLevel: "debug",
  apiKey: process.env.OPENAI_API_KEY,
});

try {
  const resp = await client.responses.create({
    model: "gpt-5",
    tools: [
      {
        type: "mcp",
        server_label: "todos",
        server_description: "A local MCP server",
        require_approval: "never",
        server_url: process.env.MCP_SERVER_URL,
        authorization: process.env.MCP_OAUTH_ACCESS_TOKEN,
      },
    ],
    input:
      "list my todos in my todos list. Always use the MCP tool to manage my todos.",
    // input: "add a todo to my todos list: 'Buy groceries'. Always use the MCP tool to manage my todos.",
  });

  console.log({ output: resp.output });
  console.log({ output: resp.output_text });
} catch (error) {
  console.error("Error details:", {
    message: error.message,
    name: error.name,
    stack: error.stack,
    cause: error.cause,
  });
}
