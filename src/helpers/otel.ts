// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import {
  useAzureMonitor,
  AzureMonitorOpenTelemetryOptions,
} from "@azure/monitor-opentelemetry";
import {
  trace,
  metrics,
  Span,
  SpanKind,
  TraceFlags,
  ProxyTracerProvider,
} from "@opentelemetry/api";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { registerInstrumentations } from "@opentelemetry/instrumentation";
import { emptyResource } from "@opentelemetry/resources";
import {
  SEMRESATTRS_SERVICE_INSTANCE_ID,
  SEMRESATTRS_SERVICE_NAME,
  SEMRESATTRS_SERVICE_NAMESPACE,
} from "@opentelemetry/semantic-conventions";
import {
  BatchSpanProcessor,
  ReadableSpan,
  SpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import { HttpInstrumentationConfig } from "@opentelemetry/instrumentation-http";
import { FsInstrumentation } from "@opentelemetry/instrumentation-fs";
import { IncomingMessage } from "node:http";
import { USER_DETAILS_ADMIN_DEMO } from "../auth/user-details-demo.js";

import { logger } from "./logs.js";
const log = logger("otel");

export function initializeTelemetry() {
  // Filter using HTTP instrumentation configuration
  const httpInstrumentationConfig: HttpInstrumentationConfig = {
    enabled: true,
    ignoreIncomingRequestHook: (request: IncomingMessage) => {
      // Ignore OPTIONS incoming requests
      if (request.method === "OPTIONS") {
        return true;
      }
      return false;
    },
  };

  const customResource = emptyResource();
  // ----------------------------------------
  // Setting role name and role instance
  // ----------------------------------------
  customResource.attributes[SEMRESATTRS_SERVICE_NAME] = "mcp-container-ts";
  customResource.attributes[SEMRESATTRS_SERVICE_NAMESPACE] = "Azure-Samples";
  customResource.attributes[SEMRESATTRS_SERVICE_INSTANCE_ID] = "instance-1";

  const options: AzureMonitorOpenTelemetryOptions = {
    // Sampling could be configured here
    samplingRatio: 1,
    enableLiveMetrics: true,
    // Use custom Resource
    resource: customResource as any,
    instrumentationOptions: {
      // Custom HTTP Instrumentation Configuration
      http: httpInstrumentationConfig,
      azureSdk: { enabled: true },
    },
  };

  if (process.env.APPLICATIONINSIGHTS_CONNECTION_STRING) {
    // Use connection string from env variable APPLICATIONINSIGHTS_CONNECTION_STRING
    options.azureMonitorExporterOptions = {
      connectionString: process.env.APPLICATIONINSIGHTS_CONNECTION_STRING,
    };
    addSpanProcessor(options);
    addOTLPExporter(options);
    useAzureMonitor(options);
    log.success("Azure Monitor OpenTelemetry initialized");
    
    // Need client to be created
    addOpenTelemetryInstrumentation();
    log.success("Azure Monitor configured successfully!");
    log.success("Connection string source: env=APPLICATIONINSIGHTS_CONNECTION_STRING");
    log.success("Telemetry will be sent to Azure Application Insights");
    log.info("Check Azure Portal > Application Insights > Live Metrics Stream");
  }
  else {
    log.warn("APPLICATIONINSIGHTS_CONNECTION_STRING not set, telemetry disabled");
  }
}

function addOpenTelemetryInstrumentation() {
  const tracerProvider = (
    trace.getTracerProvider() as ProxyTracerProvider
  ).getDelegate();
  const meterProvider = metrics.getMeterProvider();
  registerInstrumentations({
    instrumentations: [new FsInstrumentation()],
    tracerProvider: tracerProvider,
    meterProvider: meterProvider,
  });
}

function addSpanProcessor(options: AzureMonitorOpenTelemetryOptions) {
  // Custom SpanProcessor class
  class SpanEnrichingProcessor implements SpanProcessor {
    forceFlush(): Promise<void> {
      return Promise.resolve();
    }
    shutdown(): Promise<void> {
      return Promise.resolve();
    }
    onStart(_span: Span): void {}
    onEnd(span: ReadableSpan) {
      // Telemetry can be Filtered out here
      if (span.kind == SpanKind.INTERNAL) {
        span.spanContext().traceFlags = TraceFlags.NONE;
      }

      // Extra attributes could be added to the Span
      else {
        span.attributes["UserId"] = USER_DETAILS_ADMIN_DEMO.id;
        span.attributes["UserEmail"] = USER_DETAILS_ADMIN_DEMO.email;
        span.attributes["UserRole"] = USER_DETAILS_ADMIN_DEMO.role;
      }
    }
  }
  if (options.spanProcessors && options.spanProcessors.length > 0) {
    options.spanProcessors.push(new SpanEnrichingProcessor());
  } else {
    options.spanProcessors = [new SpanEnrichingProcessor()];
  }
}

function addOTLPExporter(options: AzureMonitorOpenTelemetryOptions) {
  const traceExporter = new OTLPTraceExporter();
  if (options.spanProcessors && options.spanProcessors.length > 0) {
    options.spanProcessors.push(new BatchSpanProcessor(traceExporter));
  } else {
    options.spanProcessors = [new BatchSpanProcessor(traceExporter)];
  }
}
