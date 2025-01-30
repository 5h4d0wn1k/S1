from typing import Dict, Optional
import os
from functools import wraps
import time

from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    multiprocess,
    CollectorRegistry,
    CONTENT_TYPE_LATEST,
    generate_latest
)
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from starlette.requests import Request
from starlette.responses import Response

from ..utils.logging import LoggerMixin
from ..core.settings import get_settings

settings = get_settings()
logger = LoggerMixin().get_logger()

# Prometheus metrics
REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"]
)

REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"]
)

ACTIVE_CONNECTIONS = Gauge(
    "websocket_active_connections",
    "Number of active WebSocket connections",
    ["channel"]
)

EVENTS_PROCESSED = Counter(
    "events_processed_total",
    "Total number of events processed",
    ["type", "source"]
)

ALERTS_TOTAL = Counter(
    "alerts_total",
    "Total number of alerts",
    ["severity", "status"]
)

SYSTEM_METRICS = Gauge(
    "system_metrics",
    "System metrics",
    ["metric"]
)

def setup_monitoring(app):
    """Initialize monitoring and tracing."""
    try:
        # Set up OpenTelemetry
        if settings.OTEL_ENABLED:
            tracer_provider = TracerProvider()
            processor = BatchSpanProcessor(OTLPSpanExporter())
            tracer_provider.add_span_processor(processor)
            trace.set_tracer_provider(tracer_provider)
            
            # Instrument FastAPI
            FastAPIInstrumentor.instrument_app(app)
            
            logger.info("OpenTelemetry tracing initialized")
        
        # Set up Prometheus multiprocess mode
        if "prometheus_multiproc_dir" in os.environ:
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)
        
        logger.info("Monitoring initialized successfully")
        
    except Exception as e:
        logger.error("Failed to initialize monitoring", error=e)
        raise

def track_time(name: str):
    """Decorator to track function execution time."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            
            REQUEST_DURATION.labels(
                method="function",
                endpoint=name
            ).observe(duration)
            
            return result
        return wrapper
    return decorator

async def metrics_endpoint(request: Request) -> Response:
    """Prometheus metrics endpoint."""
    try:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        
        return Response(
            generate_latest(registry),
            media_type=CONTENT_TYPE_LATEST
        )
    except Exception as e:
        logger.error("Failed to generate metrics", error=e)
        raise

def record_event(event_type: str, source: str):
    """Record an event in metrics."""
    try:
        EVENTS_PROCESSED.labels(
            type=event_type,
            source=source
        ).inc()
    except Exception as e:
        logger.error(
            "Failed to record event metric",
            error=e,
            event_type=event_type,
            source=source
        )

def record_alert(severity: str, status: str):
    """Record an alert in metrics."""
    try:
        ALERTS_TOTAL.labels(
            severity=severity,
            status=status
        ).inc()
    except Exception as e:
        logger.error(
            "Failed to record alert metric",
            error=e,
            severity=severity,
            status=status
        )

def update_system_metrics(metrics: Dict[str, float]):
    """Update system metrics."""
    try:
        for metric, value in metrics.items():
            SYSTEM_METRICS.labels(metric=metric).set(value)
    except Exception as e:
        logger.error(
            "Failed to update system metrics",
            error=e,
            metrics=metrics
        )

def update_websocket_connections(channel: str, count: int):
    """Update WebSocket connection count."""
    try:
        ACTIVE_CONNECTIONS.labels(channel=channel).set(count)
    except Exception as e:
        logger.error(
            "Failed to update WebSocket connections metric",
            error=e,
            channel=channel,
            count=count
        ) 