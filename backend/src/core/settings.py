from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """Application settings."""
    
    # Project metadata
    PROJECT_NAME: str = "Next-Gen SIEM"
    VERSION: str = "0.1.0"
    DESCRIPTION: str = "Next-generation SIEM with offensive and defensive capabilities"
    
    # API configuration
    API_V1_STR: str = "/api/v1"
    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000
    
    # Security
    SECRET_KEY: str = "your-super-secret-key"  # Change in production
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ALGORITHM: str = "HS256"
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000"]
    
    # Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "siem"
    POSTGRES_PORT: int = 5432
    POSTGRES_POOL_SIZE: int = 20
    POSTGRES_MAX_OVERFLOW: int = 10
    POSTGRES_POOL_TIMEOUT: int = 30
    
    # Elasticsearch
    ELASTICSEARCH_HOSTS: List[str] = ["http://localhost:9200"]
    ELASTICSEARCH_USERNAME: Optional[str] = None
    ELASTICSEARCH_PASSWORD: Optional[str] = None
    
    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    
    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: List[str] = ["localhost:9092"]
    KAFKA_SECURITY_PROTOCOL: str = "PLAINTEXT"
    KAFKA_SASL_MECHANISM: Optional[str] = None
    KAFKA_USERNAME: Optional[str] = None
    KAFKA_PASSWORD: Optional[str] = None
    
    # Offensive tools
    METASPLOIT_HOST: str = "localhost"
    METASPLOIT_PORT: int = 55553
    METASPLOIT_USERNAME: str = "msf"
    METASPLOIT_PASSWORD: str = "msf"
    NUCLEI_BINARY_PATH: Path = Path("/usr/local/bin/nuclei")
    
    # Defensive tools
    SURICATA_SOCKET_PATH: Path = Path("/var/run/suricata/suricata.socket")
    SURICATA_RULES_PATH: Path = Path("/etc/suricata/rules")
    WAZUH_HOST: str = "localhost"
    WAZUH_PORT: int = 55000
    WAZUH_USER: str = "wazuh"
    WAZUH_PASSWORD: str = "wazuh"
    
    # AI/ML
    AI_MODELS_PATH: Path = Path("models")
    HUGGINGFACE_TOKEN: Optional[str] = None
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    SENTRY_DSN: Optional[str] = None
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    # System
    OS_TYPE: str = "linux"  # or "windows"
    TEMP_DIR: Path = Path("/tmp")
    
    # Monitoring
    PROMETHEUS_MULTIPROC_DIR: Path = Path("/tmp/prometheus")
    PROMETHEUS_ENABLED: bool = True
    PROMETHEUS_PUSH_GATEWAY: Optional[str] = None
    PROMETHEUS_PUSH_INTERVAL: int = 10  # seconds
    
    # OpenTelemetry
    OTEL_ENABLED: bool = True
    OTEL_SERVICE_NAME: str = "siem-backend"
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://localhost:4317"
    OTEL_EXPORTER_OTLP_HEADERS: Optional[str] = None
    OTEL_SAMPLER_RATIO: float = 1.0  # Sample 100% of traces in development
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_STRATEGY: str = "fixed-window"  # or "moving-window"
    
    # WebSocket
    WS_MAX_CONNECTIONS: int = 1000
    WS_MAX_KEEPALIVE: int = 60  # seconds
    WS_PING_INTERVAL: int = 20  # seconds
    WS_PING_TIMEOUT: int = 10  # seconds
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True
    )

@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings() 