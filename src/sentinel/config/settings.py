"""
Project Sentinel Configuration Management
Handles all application settings and environment variables
"""

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    ELASTICSEARCH_URL: str = 'http://elasticsearch:9200'
    # Default aligns with .env.example; override in production
    API_KEY: str = 'change-me-very-secret'
    
    # Index names
    SOURCE_INDEX: str = 'filebeat-*'
    PROCESSED_INDEX: str = 'sentinel-events'

    # Optional basic auth for secured Elasticsearch
    ELASTICSEARCH_USERNAME: str | None = None
    ELASTICSEARCH_PASSWORD: str | None = None

    # Optional TLS controls
    ELASTICSEARCH_VERIFY_CERTS: bool = True
    ELASTICSEARCH_CA_CERTS: str | None = None

    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

settings = Settings()
