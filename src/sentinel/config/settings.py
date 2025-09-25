"""
Project Sentinel Configuration Management
Handles all application settings and environment variables
"""

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScoringWeights(BaseModel):
    """Defines the weights for various risk factors."""
    login_success: int = 80
    login_failed: int = 10
    privileged_account: int = 15
    command_input: int = 5
    suspicious_command: int = 30
    file_transfer: int = 40
    geo_risk: int = 10
    night_activity: int = 5
    ip_reputation_risk: int = 50


class Settings(BaseSettings):
    ELASTICSEARCH_URL: str = 'http://elasticsearch:9200'
    API_KEY: str
    
    # Index names
    SOURCE_INDEX: str = 'filebeat-*'
    PROCESSED_INDEX: str = 'sentinel-events'

    # Optional basic auth for secured Elasticsearch
    ELASTICSEARCH_USERNAME: str | None = None
    ELASTICSEARCH_PASSWORD: str | None = None

    # Optional TLS controls
    ELASTICSEARCH_VERIFY_CERTS: bool = True
    ELASTICSEARCH_CA_CERTS: str | None = None

    # Application settings
    HIGH_RISK_SCORE_THRESHOLD: int = 70
    GEOIP_RISK_COUNTRIES: list[str] = ['Russian Federation', 'China', 'Iran']
    SUSPICIOUS_COMMANDS: list[str] = ['wget', 'curl', 'nc', 'netcat', 'nmap', 'chmod 777']
    API_EVENT_LIMIT: int = 1000
    SCORING_WEIGHTS: ScoringWeights = Field(default_factory=ScoringWeights)
 
    model_config = SettingsConfigDict(
        env_file='.env',
        extra='ignore',
        env_nested_delimiter='__'
    )

settings = Settings()