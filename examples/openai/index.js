import "dotenv/config";
import OpenAI from "openai";

const client = new OpenAI({
  logLevel: "debug",
  apiKey: process.env.API_KEY,
});

try {
  const resp = await client.responses.create({
    model: "gpt-5",
    tools: [
      {
        type: "mcp",
        server_label: "todos",
        server_description: "A simple TODO MCP server to manage your todos",
        require_approval: "never",
        server_url: process.env.MCP_SERVER_URL,
        authorization: process.env.MCP_JWT_TOKEN,
      },
    ],
    input:
      "list my todos in my todos list. Always use the MCP tool to manage my todos.",
    // input: "add a todo to my todos list: 'Buy groceries'. Always use the MCP tool to manage my todos.",
    // input: `I'd like to see a list of all my todos.`,
    // input: `Please add a todo: "Learn about MCP"`,
    // input: `Mark todo #1 as completed.`,
    // input: `Delete todo #2.`,
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
