import type { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse";

export const TransportsCache = new Map<string, SSEServerTransport>();