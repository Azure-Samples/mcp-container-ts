import EventEmitter from 'node:events';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { trace, SpanStatusCode } from '@opentelemetry/api';
import { logger } from './helpers/logs.js';

const log = logger('host');

export class MCPClient extends EventEmitter {
  private client: Client;
  private transport: StreamableHTTPClientTransport;

  constructor(serverName: string, serverUrl: string, accessToken?: string) {
    const tracer = trace.getTracer('mcp-client');
    const span = tracer.startSpan('client.constructor', {
      attributes: {
        'client.server_name': serverName,
        'client.server_url': serverUrl,
        'client.has_access_token': !!accessToken,
        'client.name': 'mcp-client-' + serverName,
        'client.version': '1.0.0',
      },
    });
    
    try {
      super();
      this.client = new Client({
        name: 'mcp-client-' + serverName,
        version: '1.0.0',
      });

      let headers = {};

      if (accessToken) {
        headers = {
          Authorization: 'Bearer ' + accessToken,
        };
        span.addEvent('auth.token_configured');
      }

      this.transport = new StreamableHTTPClientTransport(new URL(serverUrl), {
        requestInit: {
          headers: {
            ...headers,
          },
        },
      });

      this.client.setNotificationHandler(
        ToolListChangedNotificationSchema,
        () => {
          log.info('Emitting toolListChanged event');
          span.addEvent('notification.tool_list_changed');
          this.emit('toolListChanged');
        }
      );
      
      span.setStatus({
        code: SpanStatusCode.OK,
        message: 'MCP Client initialized successfully',
      });
      
      span.addEvent('client.initialized', {
        'server_name': serverName,
        'server_url': serverUrl,
      });
    } catch (error) {
      span.addEvent('client.initialization_error', {
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

  async connect() {
    const tracer = trace.getTracer('mcp-client');
    const span = tracer.startSpan('client.connect');
    
    try {
      const startTime = Date.now();
      await this.client.connect(this.transport);
      const connectionTime = Date.now() - startTime;
      
      span.setAttributes({
        'connection.time_ms': connectionTime,
        'connection.success': true,
      });
      
      span.addEvent('client.connected', {
        'connection_time_ms': connectionTime,
      });
      
      span.setStatus({
        code: SpanStatusCode.OK,
        message: 'Connected to MCP server',
      });
      
      log.success('Connected to server');
    } catch (error) {
      span.addEvent('client.connection_error', {
        'error.message': error instanceof Error ? error.message : String(error),
        'error.name': error instanceof Error ? error.name : 'unknown',
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

  async getAvailableTools() {
    const tracer = trace.getTracer('mcp-client');
    const span = tracer.startSpan('client.getAvailableTools');
    
    try {
      const startTime = Date.now();
      const result = await this.client.listTools();
      const executionTime = Date.now() - startTime;
      
      const toolNames = result.tools.map(tool => tool.name);
      
      span.setAttributes({
        'tools.count': result.tools.length,
        'tools.names': toolNames.join(','),
        'request.execution_time_ms': executionTime,
        'operation.success': true,
      });
      
      span.addEvent('tools.listed', {
        'tools_count': result.tools.length,
        'execution_time_ms': executionTime,
        'tool_names': toolNames,
      });
      
      span.setStatus({
        code: SpanStatusCode.OK,
        message: `Retrieved ${result.tools.length} available tools`,
      });
      
      return result.tools;
    } catch (error) {
      span.addEvent('tools.list_error', {
        'error.message': error instanceof Error ? error.message : String(error),
        'error.name': error instanceof Error ? error.name : 'unknown',
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

  async callTool(name: string, toolArgs: string) {
    const tracer = trace.getTracer('mcp-client');
    const span = tracer.startSpan('client.callTool', {
      attributes: {
        'tool.name': name,
        'tool.arguments': toolArgs,
        'tool.arguments_length': toolArgs.length,
      },
    });
    
    try {
      log.info(`Calling tool ${name} with arguments:`, toolArgs);
      
      let parsedArgs: any;
      try {
        parsedArgs = JSON.parse(toolArgs);
        span.addEvent('arguments.parsed', {
          'arguments_keys': Object.keys(parsedArgs).join(','),
          'arguments_count': Object.keys(parsedArgs).length,
        });
      } catch (parseError) {
        span.addEvent('arguments.parse_error', {
          'error.message': parseError instanceof Error ? parseError.message : String(parseError),
          'raw_arguments': toolArgs,
        });
        throw new Error(`Failed to parse tool arguments: ${parseError}`);
      }
      
      const startTime = Date.now();
      const result = await this.client.callTool({
        name,
        arguments: parsedArgs,
      });
      const executionTime = Date.now() - startTime;
      
      const contentLength = Array.isArray(result.content) ? result.content.length : 0;
      
      span.setAttributes({
        'tool.execution_time_ms': executionTime,
        'tool.result_content_items': contentLength,
        'operation.success': true,
      });
      
      span.addEvent('tool.call_completed', {
        'tool_name': name,
        'execution_time_ms': executionTime,
        'result_content_items': contentLength,
      });
      
      span.setStatus({
        code: SpanStatusCode.OK,
        message: `Tool ${name} executed successfully`,
      });
      
      return result;
    } catch (error) {
      span.addEvent('tool.call_error', {
        'error.message': error instanceof Error ? error.message : String(error),
        'error.name': error instanceof Error ? error.name : 'unknown',
        'tool.name': name,
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

  async close() {
    const tracer = trace.getTracer('mcp-client');
    const span = tracer.startSpan('client.close');
    
    try {
      log.info('Closing transport...');
      
      const startTime = Date.now();
      await this.transport.close();
      const closeTime = Date.now() - startTime;
      
      span.setAttributes({
        'close.time_ms': closeTime,
        'operation.success': true,
      });
      
      span.addEvent('client.closed', {
        'close_time_ms': closeTime,
      });
      
      span.setStatus({
        code: SpanStatusCode.OK,
        message: 'MCP client closed successfully',
      });
    } catch (error) {
      span.addEvent('client.close_error', {
        'error.message': error instanceof Error ? error.message : String(error),
        'error.name': error instanceof Error ? error.name : 'unknown',
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
}