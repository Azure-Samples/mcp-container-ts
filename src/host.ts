import "dotenv/config";
import OpenAI from "openai";
import { ChatCompletionStreamingRunner } from "openai/lib/ChatCompletionStreamingRunner";
import { RunnableToolFunctionWithoutParse } from "openai/lib/RunnableFunction";
import { MCPClient } from "./client.js";
const model = "ai/phi4:14B-Q4_0";
const accessToken = process.env.JWT_TOKEN;
const usage: OpenAI.Completions.CompletionUsage[] = [];

function zodSchemaToParametersSchema(zodSchema: any): {
  type: string;
  properties: Record<string, any>;
  required: string[];
  additionalProperties: boolean;
} {
  const properties: Record<string, any> = zodSchema.properties || {};
  const required: string[] = zodSchema.required || [];
  const additionalProperties: boolean =
    zodSchema.additionalProperties !== undefined
      ? zodSchema.additionalProperties
      : false;

  return {
    type: "object",
    properties,
    required,
    additionalProperties,
  };
}

function mcpToolToOpenAiToolChatCompletion(tool: {
  name: string;
  description?: string;
  inputSchema: any;
}): (RunnableToolFunctionWithoutParse) {
  return {
    type: "function",
    function: {
      strict: true,
      name: tool.name,
      function: (args: any) => {},
      description: tool.description || '',
      parameters: {
        ...zodSchemaToParametersSchema(tool.inputSchema),
      },
    },
  };
}

function streamingRunnerListener(runner: ChatCompletionStreamingRunner<any>) {
  runner
    .on("connect", () => console.log("Connected to the streaming runner."))
    .on("chunk", (chunk) => {
      console.log("Received chunk:", { chunk });
      if (chunk.usage) usage.push(chunk.usage);
    })
    .on("content", (delta, snapshot) =>
      console.log("Received content:", { delta, snapshot })
    )
    .on("message", (message) => console.log("Received message:", { message }))
    .on("chatCompletion", (completion) =>
      console.log("Received chat completion:", { completion })
    )
    .on("functionToolCall", (functionCall) =>
      console.log("Received function tool call:", { functionCall })
    )
    .on("functionToolCallResult", (result) =>
      console.log("Received function tool call result:", { result })
    )
    .on("finalContent", (content) =>
      console.log("Received final content:", { content })
    )
    .on("finalMessage", (message) =>
      console.log("Received final message:", { message })
    )
    .on("finalChatCompletion", (completion) =>
      console.log("Received final chat completion:", { completion })
    )
    .on("finalFunctionToolCall", (functionCall) =>
      console.log("Received final function tool call:", { functionCall })
    )
    .on("finalFunctionToolCallResult", (result) =>
      console.log("Received final function tool call result:", { result })
    )
    .on("error", (error) => console.log("Error during streaming:", { error }))
    .on("abort", (abort) => console.log("Streaming aborted:", { abort }))
    .on("end", () => {
      console.log("Streaming ended.");
      if (usage.length > 0) {
        console.log("Usage statistics:", {
          total_tokens: usage.reduce((sum, u) => sum + u.total_tokens, 0),
          prompt_tokens: usage.reduce((sum, u) => sum + u.prompt_tokens, 0),
          completion_tokens: usage.reduce(
            (sum, u) => sum + u.completion_tokens,
            0
          ),
        });
      }
    });
}

try {
  const  mcp = new MCPClient('todo-server', 'http://localhost:3000/mcp', accessToken);
  await mcp.connect();
  console.log("fetching tools...");
  const mcpTools: (RunnableToolFunctionWithoutParse[]) = (await mcp.getAvailableTools()).map(mcpToolToOpenAiToolChatCompletion);
  console.log("tools fetched:", {mcpTools});
  const client = new OpenAI({
    baseURL: "http://localhost:12434/engines/llama.cpp/v1",
    apiKey: "DOCKER_API_KEY",
  });
  streamingRunnerListener(
    client.chat.completions.runTools({
      model,
      messages: [
        { role: "developer", content: "You are my TODO assistant. Always call the addTodo tool function." },
        {
          role: "user",
          content: 'I have a TODO list. Add "Buy milk" to the list.',
        },
      ],
      tools: mcpTools,
      stream: true,
      stream_options: { include_usage: true },
    })
  );

}
catch (error: any) {
  console.error(error.message);
}

