from typing import Dict, Any

# Common field mappings
COMMON_FIELDS = {
    "properties": {
        "@timestamp": {
            "type": "date"
        },
        "@version": {
            "type": "keyword"
        },
        "host": {
            "properties": {
                "name": {"type": "keyword"},
                "ip": {"type": "ip"},
                "os": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "version": {"type": "keyword"},
                        "family": {"type": "keyword"}
                    }
                }
            }
        },
        "tags": {
            "type": "keyword"
        },
        "metadata": {
            "type": "object",
            "dynamic": True
        }
    }
}

# Log index template
LOG_TEMPLATE: Dict[str, Any] = {
    "index_patterns": ["logs-*"],
    "template": {
        "settings": {
            "number_of_shards": 3,
            "number_of_replicas": 1,
            "index.lifecycle.name": "logs-policy",
            "index.lifecycle.rollover_alias": "logs",
            "index.mapping.total_fields.limit": 2000,
            "index.mapping.ignore_malformed": True,
            "analysis": {
                "analyzer": {
                    "path_analyzer": {
                        "type": "custom",
                        "tokenizer": "path_tokenizer"
                    }
                },
                "tokenizer": {
                    "path_tokenizer": {
                        "type": "path_hierarchy",
                        "delimiter": "/"
                    }
                }
            }
        },
        "mappings": {
            "dynamic_templates": [
                {
                    "strings_as_keywords": {
                        "match_mapping_type": "string",
                        "mapping": {
                            "type": "keyword",
                            "ignore_above": 1024,
                            "fields": {
                                "text": {
                                    "type": "text",
                                    "norms": False
                                }
                            }
                        }
                    }
                }
            ],
            "properties": {
                **COMMON_FIELDS["properties"],
                "message": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "level": {
                    "type": "keyword"
                },
                "logger": {
                    "type": "keyword"
                },
                "thread": {
                    "type": "keyword"
                },
                "request_id": {
                    "type": "keyword"
                },
                "source": {
                    "type": "keyword"
                },
                "source_ip": {
                    "type": "ip"
                },
                "destination_ip": {
                    "type": "ip"
                },
                "user_id": {
                    "type": "keyword"
                },
                "session_id": {
                    "type": "keyword"
                },
                "response_time": {
                    "type": "float"
                },
                "bytes": {
                    "type": "long"
                },
                "status_code": {
                    "type": "short"
                },
                "path": {
                    "type": "keyword",
                    "fields": {
                        "hierarchy": {
                            "type": "text",
                            "analyzer": "path_analyzer"
                        }
                    }
                },
                "method": {
                    "type": "keyword"
                },
                "user_agent": {
                    "type": "keyword",
                    "fields": {
                        "text": {
                            "type": "text"
                        }
                    }
                },
                "error": {
                    "properties": {
                        "type": {"type": "keyword"},
                        "message": {"type": "text"},
                        "stack_trace": {"type": "text"},
                        "code": {"type": "keyword"}
                    }
                }
            }
        }
    }
}

# Alert index template
ALERT_TEMPLATE: Dict[str, Any] = {
    "index_patterns": ["alerts-*"],
    "template": {
        "settings": {
            "number_of_shards": 2,
            "number_of_replicas": 1,
            "index.lifecycle.name": "alerts-policy",
            "index.lifecycle.rollover_alias": "alerts"
        },
        "mappings": {
            "properties": {
                **COMMON_FIELDS["properties"],
                "title": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "description": {
                    "type": "text"
                },
                "severity": {
                    "type": "keyword"
                },
                "status": {
                    "type": "keyword"
                },
                "source": {
                    "type": "keyword"
                },
                "source_id": {
                    "type": "keyword"
                },
                "asset_id": {
                    "type": "keyword"
                },
                "scan_id": {
                    "type": "keyword"
                },
                "assignee": {
                    "type": "keyword"
                },
                "resolved_at": {
                    "type": "date"
                },
                "resolved_by": {
                    "type": "keyword"
                },
                "context": {
                    "type": "object",
                    "dynamic": True
                },
                "ai_analysis": {
                    "properties": {
                        "classification": {
                            "properties": {
                                "label": {"type": "keyword"},
                                "score": {"type": "float"}
                            }
                        },
                        "summary": {"type": "text"},
                        "confidence": {"type": "float"},
                        "analyzed_at": {"type": "date"}
                    }
                },
                "mitre_attack": {
                    "properties": {
                        "tactics": {"type": "keyword"},
                        "techniques": {"type": "keyword"}
                    }
                },
                "indicators": {
                    "properties": {
                        "type": {"type": "keyword"},
                        "value": {"type": "keyword"},
                        "confidence": {"type": "float"}
                    }
                }
            }
        }
    }
}

# ILM Policies
LOG_ILM_POLICY = {
    "policy": {
        "phases": {
            "hot": {
                "min_age": "0ms",
                "actions": {
                    "rollover": {
                        "max_age": "1d",
                        "max_size": "50gb"
                    },
                    "set_priority": {
                        "priority": 100
                    }
                }
            },
            "warm": {
                "min_age": "2d",
                "actions": {
                    "shrink": {
                        "number_of_shards": 1
                    },
                    "forcemerge": {
                        "max_num_segments": 1
                    },
                    "set_priority": {
                        "priority": 50
                    }
                }
            },
            "cold": {
                "min_age": "7d",
                "actions": {
                    "set_priority": {
                        "priority": 0
                    }
                }
            },
            "delete": {
                "min_age": "30d",
                "actions": {
                    "delete": {}
                }
            }
        }
    }
}

ALERT_ILM_POLICY = {
    "policy": {
        "phases": {
            "hot": {
                "min_age": "0ms",
                "actions": {
                    "rollover": {
                        "max_age": "7d",
                        "max_size": "50gb"
                    },
                    "set_priority": {
                        "priority": 100
                    }
                }
            },
            "warm": {
                "min_age": "30d",
                "actions": {
                    "set_priority": {
                        "priority": 50
                    }
                }
            },
            "cold": {
                "min_age": "90d",
                "actions": {
                    "set_priority": {
                        "priority": 0
                    }
                }
            },
            "delete": {
                "min_age": "365d",
                "actions": {
                    "delete": {}
                }
            }
        }
    }
} 