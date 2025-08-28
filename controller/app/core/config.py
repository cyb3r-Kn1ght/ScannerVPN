# app/core/config.py
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database configuration
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data/scan_results.db")

    # Service URLs
    SCANNER_NODE_URL: str = os.getenv("SCANNER_NODE_URL", "http://scanner-node-api:8000")
    CONTROLLER_CALLBACK_URL: str = os.getenv("CONTROLLER_CALLBACK_URL", "http://controller:8000")
    VPN_PROXY_NODE: str = os.getenv("VPN_PROXY_NODE", "http://10.102.199.221:8000")

    # Project Information
    PROJECT_NAME: str = "Distributed Scanner Controller"
    API_V1_STR: str = "/api/v1"

    class Config:
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = 'utf-8'

settings = Settings()