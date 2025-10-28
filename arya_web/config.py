import os
from pathlib import Path


class Config:
    # ARYA Cognito config (defaults from current single-file app)
    USER_POOL_ID = os.getenv("ARYA_USER_POOL_ID", "eu-central-1_sjczhcQCX")
    CLIENT_ID = os.getenv("ARYA_CLIENT_ID", "at6lgqnsnrjtbhrl30s6knvns")
    REGION = os.getenv("ARYA_REGION", "eu-central-1")

    # Hosts
    CLOUD_HOST = os.getenv("ARYA_CLOUD_HOST", "https://arya.spinetix.cloud")
    SERVICES_HOST = os.getenv("ARYA_SERVICES_HOST", "https://arya.services.spinetix.com")

    # Secret key (override in production)
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-secret")

    # Local files
    CACHE_PATH = Path(os.getenv("ARYA_CACHE_PATH", ".arya_tokens.json"))
    LOGIN_FILE_PATH = Path(os.getenv("ARYA_LOGIN_FILE", "login.json"))

