"""
Project Sentinel Configuration Management
Handles all application settings and environment variables
"""

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    ELASTICSEARCH_URL: str = 'http://elasticsearch:9200'
    API_KEY: str = 'your-secret-api-key-12345'
    
    # Index names
    SOURCE_INDEX: str = 'filebeat-*'
    PROCESSED_INDEX: str = 'sentinel-events'

    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

settings = Settings()
