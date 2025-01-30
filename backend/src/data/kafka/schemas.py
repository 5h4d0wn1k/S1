from typing import Dict, Any

# Common fields for all schemas
COMMON_FIELDS = [
    {"name": "@timestamp", "type": "long", "logicalType": "timestamp-millis"},
    {"name": "@version", "type": "string"},
    {
        "name": "host",
        "type": "record",
        "fields": [
            {"name": "name", "type": "string"},
            {"name": "ip", "type": "string"},
            {
                "name": "os",
                "type": "record",
                "fields": [
                    {"name": "name", "type": ["null", "string"]},
                    {"name": "version", "type": ["null", "string"]},
                    {"name": "family", "type": ["null", "string"]}
                ]
            }
        ]
    },
    {"name": "tags", "type": {"type": "array", "items": "string"}, "default": []},
    {"name": "metadata", "type": {"type": "map", "values": "string"}, "default": {}}
]

# Log schema
LOG_SCHEMA: Dict[str, Any] = {
    "type": "record",
    "name": "Log",
    "namespace": "com.siem.schemas",
    "fields": [
        *COMMON_FIELDS,
        {"name": "message", "type": "string"},
        {"name": "level", "type": "string"},
        {"name": "logger", "type": "string"},
        {"name": "thread", "type": ["null", "string"]},
        {"name": "request_id", "type": ["null", "string"]},
        {"name": "source", "type": "string"},
        {"name": "source_ip", "type": ["null", "string"]},
        {"name": "destination_ip", "type": ["null", "string"]},
        {"name": "user_id", "type": ["null", "string"]},
        {"name": "session_id", "type": ["null", "string"]},
        {"name": "response_time", "type": ["null", "double"]},
        {"name": "bytes", "type": ["null", "long"]},
        {"name": "status_code", "type": ["null", "int"]},
        {"name": "path", "type": ["null", "string"]},
        {"name": "method", "type": ["null", "string"]},
        {"name": "user_agent", "type": ["null", "string"]},
        {
            "name": "error",
            "type": ["null", {
                "type": "record",
                "name": "Error",
                "fields": [
                    {"name": "type", "type": "string"},
                    {"name": "message", "type": "string"},
                    {"name": "stack_trace", "type": ["null", "string"]},
                    {"name": "code", "type": ["null", "string"]}
                ]
            }]
        }
    ]
}

# Alert schema
ALERT_SCHEMA: Dict[str, Any] = {
    "type": "record",
    "name": "Alert",
    "namespace": "com.siem.schemas",
    "fields": [
        *COMMON_FIELDS,
        {"name": "id", "type": "string"},
        {"name": "title", "type": "string"},
        {"name": "description", "type": "string"},
        {"name": "severity", "type": {"type": "enum", "name": "Severity", "symbols": ["critical", "high", "medium", "low", "info"]}},
        {"name": "status", "type": {"type": "enum", "name": "Status", "symbols": ["new", "in_progress", "resolved", "false_positive"]}},
        {"name": "source", "type": "string"},
        {"name": "source_id", "type": ["null", "string"]},
        {"name": "asset_id", "type": ["null", "string"]},
        {"name": "scan_id", "type": ["null", "string"]},
        {"name": "assignee", "type": ["null", "string"]},
        {"name": "resolved_at", "type": ["null", {"type": "long", "logicalType": "timestamp-millis"}]},
        {"name": "resolved_by", "type": ["null", "string"]},
        {"name": "context", "type": {"type": "map", "values": ["null", "string", "long", "double", "boolean"]}},
        {
            "name": "ai_analysis",
            "type": ["null", {
                "type": "record",
                "name": "AIAnalysis",
                "fields": [
                    {
                        "name": "classification",
                        "type": {
                            "type": "record",
                            "name": "Classification",
                            "fields": [
                                {"name": "label", "type": "string"},
                                {"name": "score", "type": "double"}
                            ]
                        }
                    },
                    {"name": "summary", "type": "string"},
                    {"name": "confidence", "type": "double"},
                    {"name": "analyzed_at", "type": {"type": "long", "logicalType": "timestamp-millis"}}
                ]
            }]
        },
        {
            "name": "mitre_attack",
            "type": ["null", {
                "type": "record",
                "name": "MitreAttack",
                "fields": [
                    {"name": "tactics", "type": {"type": "array", "items": "string"}},
                    {"name": "techniques", "type": {"type": "array", "items": "string"}}
                ]
            }]
        }
    ]
}

# Scan schema
SCAN_SCHEMA: Dict[str, Any] = {
    "type": "record",
    "name": "Scan",
    "namespace": "com.siem.schemas",
    "fields": [
        *COMMON_FIELDS,
        {"name": "id", "type": "string"},
        {"name": "type", "type": {"type": "enum", "name": "ScanType", "symbols": ["vulnerability", "compliance", "penetration", "configuration"]}},
        {"name": "target_id", "type": "string"},
        {"name": "target_type", "type": "string"},
        {"name": "configuration", "type": {"type": "map", "values": ["null", "string", "long", "double", "boolean"]}},
        {"name": "status", "type": {"type": "enum", "name": "ScanStatus", "symbols": ["pending", "running", "completed", "failed", "cancelled"]}},
        {"name": "findings", "type": ["null", {"type": "map", "values": ["null", "string", "long", "double", "boolean"]}]},
        {"name": "notes", "type": ["null", "string"]},
        {"name": "schedule", "type": ["null", "string"]},
        {"name": "created_by", "type": "string"},
        {"name": "start_time", "type": ["null", {"type": "long", "logicalType": "timestamp-millis"}]},
        {"name": "end_time", "type": ["null", {"type": "long", "logicalType": "timestamp-millis"}]}
    ]
}

# Metric schema
METRIC_SCHEMA: Dict[str, Any] = {
    "type": "record",
    "name": "Metric",
    "namespace": "com.siem.schemas",
    "fields": [
        *COMMON_FIELDS,
        {"name": "name", "type": "string"},
        {"name": "value", "type": "double"},
        {"name": "unit", "type": "string"},
        {"name": "type", "type": {"type": "enum", "name": "MetricType", "symbols": ["gauge", "counter", "histogram"]}},
        {"name": "interval", "type": ["null", "long"]},
        {
            "name": "labels",
            "type": {
                "type": "map",
                "values": "string"
            },
            "default": {}
        },
        {
            "name": "histogram_values",
            "type": ["null", {
                "type": "array",
                "items": {
                    "type": "record",
                    "name": "HistogramBucket",
                    "fields": [
                        {"name": "le", "type": "double"},
                        {"name": "count", "type": "long"}
                    ]
                }
            }]
        }
    ]
} 