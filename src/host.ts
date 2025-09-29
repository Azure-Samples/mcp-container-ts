import "dotenv/config";
import { trace, SpanStatusCode } from "@opentelemetry/api";
import OpenAI from "openai";
import { ChatCompletionStreamingRunner } from "openai/lib/ChatCompletionStreamingRunner";
import { RunnableToolFunctionWithoutParse } from "openai/lib/RunnableFunction";
import { MCPClient } from "./client.js";
import { logger } from "./helpers/logs.js";
const model = "ai/phi4:14B-Q4_0";
const accessToken = process.env.JWT_TOKEN;
const usage: OpenAI.Completions.CompletionUsage[] = [];
const log = logger("host");

function zodSchemaToParametersSchema(zodSchema: any): {
  type: string;
  properties: Record<string, any>;
  required: string[];
  additionalProperties: boolean;
} {
  const tracer = trace.getTracer('host-integration');
  const span = tracer.startSpan('schema.zod_to_parameters', {
    attributes: {
      'schema.has_properties': !!(zodSchema.properties),
      'schema.has_required': !!(zodSchema.required),
      'schema.properties_count': zodSchema.properties ? Object.keys(zodSchema.properties).length : 0,
    },
  });
  
  try {
    const properties: Record<string, any> = zodSchema.properties || {};
    const required: string[] = zodSchema.required || [];
    const additionalProperties: boolean =
      zodSchema.additionalProperties !== undefined
        ? zodSchema.additionalProperties
        : false;
    
    span.setAttributes({
      'schema.properties_count': Object.keys(properties).length,
      'schema.required_count': required.length,
      'schema.additional_properties': additionalProperties,
    });
    
    span.addEvent('schema.conversion_completed', {
      'properties_count': Object.keys(properties).length,
      'required_fields': required.join(','),
    });
    
    span.setStatus({
      code: SpanStatusCode.OK,
      message: 'Schema conversion completed',
    });

    return {
      type: "object",
      properties,
      required,
      additionalProperties,
    };
  } catch (error) {
    span.addEvent('schema.conversion_error', {
      'error.message': error instanceof Error ? error.message : String(error),
    });
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  } finally {
    span.end();
  }
}

function mcpToolToOpenAiToolChatCompletion(tool: {
  name: string;
  description?: string;
  inputSchema: any;
}): (RunnableToolFunctionWithoutParse) {
  const tracer = trace.getTracer('host-integration');
  const span = tracer.startSpan('tool.mcp_to_openai_conversion', {
    attributes: {
      'tool.name': tool.name,
      'tool.has_description': !!tool.description,
      'tool.description_length': tool.description?.length || 0,
      'tool.has_input_schema': !!tool.inputSchema,
    },
  });
  
  try {
    const result = {
      type: "function" as const,
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
    
    span.addEvent('tool.conversion_completed', {
      'tool.name': tool.name,
      'tool.function_strict': true,
    });
    
    span.setStatus({
      code: SpanStatusCode.OK,
      message: 'Tool conversion completed',
    });
    
    return result;
  } catch (error) {
    span.addEvent('tool.conversion_error', {
      'error.message': error instanceof Error ? error.message : String(error),
      'tool.name': tool.name,
    });
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  } finally {
    span.end();
  }
}

function streamingRunnerListener(runner: ChatCompletionStreamingRunner<any>) {
  const tracer = trace.getTracer('host-integration');
  const streamingSpan = tracer.startSpan('openai.streaming_session', {
    attributes: {
      'streaming.model': model,
      'streaming.has_tools': true,
    },
  });
  
  let chunkCount = 0;
  let contentLength = 0;
  let functionCallCount = 0;
  
  runner
    .on("connect", () => {
      streamingSpan.addEvent('streaming.connected');
      log.info("Connected to the streaming runner.");
    })
    .on("chunk", (chunk) => {
      chunkCount++;
      streamingSpan.addEvent('streaming.chunk_received', {
        'chunk.number': chunkCount,
        'chunk.has_usage': !!chunk.usage,
      });
      log.info("Received chunk:", { chunk });
      if (chunk.usage) usage.push(chunk.usage);
    })
    .on("content", (delta, snapshot) => {
      contentLength += delta?.length || 0;
      streamingSpan.addEvent('streaming.content_received', {
        'content.delta_length': delta?.length || 0,
        'content.total_length': contentLength,
      });
      log.info("Received content:", { delta, snapshot });
    })
    .on("message", (message) => {
      streamingSpan.addEvent('streaming.message_received', {
        'message.role': message.role,
        'message.has_content': !!message.content,
      });
      log.info("Received message:", { message });
    })
    .on("chatCompletion", (completion) => {
      streamingSpan.addEvent('streaming.completion_received', {
        'completion.choices_count': completion.choices?.length || 0,
      });
      log.info("Received chat completion:", { completion });
    })
    .on("functionToolCall", (functionCall) => {
      functionCallCount++;
      streamingSpan.addEvent('streaming.function_call', {
        'function.name': (functionCall as any).function?.name,
        'function.call_number': functionCallCount,
      });
      log.info("Received function tool call:", { functionCall });
    })
    .on("functionToolCallResult", (result) => {
      streamingSpan.addEvent('streaming.function_result', {
        'result.has_content': !!(result as any).content,
      });
      log.info("Received function tool call result:", { result });
    })
    .on("finalContent", (content) => {
      streamingSpan.addEvent('streaming.final_content', {
        'content.length': content?.length || 0,
      });
      log.info("Received final content:", { content });
    })
    .on("finalMessage", (message) => {
      streamingSpan.addEvent('streaming.final_message', {
        'message.role': message.role,
      });
      log.info("Received final message:", { message });
    })
    .on("finalChatCompletion", (completion) => {
      streamingSpan.addEvent('streaming.final_completion', {
        'completion.choices_count': completion.choices?.length || 0,
      });
      log.info("Received final chat completion:", { completion });
    })
    .on("finalFunctionToolCall", (functionCall) => {
      streamingSpan.addEvent('streaming.final_function_call', {
        'function.name': (functionCall as any).function?.name,
      });
      log.info("Received final function tool call:", { functionCall });
    })
    .on("finalFunctionToolCallResult", (result) => {
      streamingSpan.addEvent('streaming.final_function_result');
      log.info("Received final function tool call result:", { result });
    })
    .on("error", (error) => {
      streamingSpan.addEvent('streaming.error', {
        'error.message': error instanceof Error ? error.message : String(error),
      });
      streamingSpan.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : String(error),
      });
      log.error("Error during streaming:", { error });
    })
    .on("abort", (abort) => {
      streamingSpan.addEvent('streaming.aborted');
      streamingSpan.setStatus({
        code: SpanStatusCode.ERROR,
        message: 'Streaming aborted',
      });
      log.warn("Streaming aborted:", { abort });
    })
    .on("end", () => {
      streamingSpan.setAttributes({
        'streaming.total_chunks': chunkCount,
        'streaming.total_content_length': contentLength,
        'streaming.function_calls_count': functionCallCount,
        'streaming.total_usage_records': usage.length,
      });
      
      if (usage.length > 0) {
        const totalTokens = usage.reduce((sum, u) => sum + u.total_tokens, 0);
        const promptTokens = usage.reduce((sum, u) => sum + u.prompt_tokens, 0);
        const completionTokens = usage.reduce((sum, u) => sum + u.completion_tokens, 0);
        
        streamingSpan.setAttributes({
          'usage.total_tokens': totalTokens,
          'usage.prompt_tokens': promptTokens,
          'usage.completion_tokens': completionTokens,
        });
        
        streamingSpan.addEvent('streaming.usage_summary', {
          'total_tokens': totalTokens,
          'prompt_tokens': promptTokens,
          'completion_tokens': completionTokens,
        });
        
        log.info("Usage statistics:", {
          total_tokens: totalTokens,
          prompt_tokens: promptTokens,
          completion_tokens: completionTokens,
        });
      }
      
      streamingSpan.addEvent('streaming.completed');
      streamingSpan.setStatus({
        code: SpanStatusCode.OK,
        message: 'Streaming completed successfully',
      });
      streamingSpan.end();
      
      log.info("Streaming ended.");
    });
}

try {
  const tracer = trace.getTracer('host-integration');
  const mainSpan = tracer.startSpan('host.main_execution', {
    attributes: {
      'model': model,
      'has_access_token': !!accessToken,
    },
  });
  
  try {
    log.info('Initializing MCP client...');
    const mcp = new MCPClient('todo-server', 'http://localhost:3000/mcp', accessToken);
    
    mainSpan.addEvent('mcp.client_created');
    await mcp.connect();
    mainSpan.addEvent('mcp.connected');
    
    log.info("Fetching tools...");
    const startTime = Date.now();
    const tools = await mcp.getAvailableTools();
    const toolFetchTime = Date.now() - startTime;
    
    mainSpan.setAttributes({
      'tools.count': tools.length,
      'tools.fetch_time_ms': toolFetchTime,
    });
    
    mainSpan.addEvent('tools.fetched', {
      'tools_count': tools.length,
      'fetch_time_ms': toolFetchTime,
    });
    
    const mcpTools: (RunnableToolFunctionWithoutParse[]) = tools.map(mcpToolToOpenAiToolChatCompletion);
    
    mainSpan.addEvent('tools.converted_to_openai', {
      'converted_tools_count': mcpTools.length,
    });
    
    log.info("Tools fetched:", { toolCount: mcpTools.length });
    
    const client = new OpenAI({
      baseURL: "http://localhost:12434/engines/llama.cpp/v1",
      apiKey: "DOCKER_API_KEY",
    });
    
    mainSpan.addEvent('openai.client_created', {
      'base_url': 'http://localhost:12434/engines/llama.cpp/v1',
    });
    
    log.info('Starting streaming chat completion...');
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
    
    mainSpan.addEvent('openai.streaming_started');
    mainSpan.setStatus({
      code: SpanStatusCode.OK,
      message: 'Host integration completed successfully',
    });
  } catch (error) {
    mainSpan.addEvent('host.execution_error', {
      'error.message': error instanceof Error ? error.message : String(error),
    });
    mainSpan.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  } finally {
    mainSpan.end();
  }
} catch (error: any) {
  log.error('Host execution error:', error.message);
  console.error(error.message);
}

