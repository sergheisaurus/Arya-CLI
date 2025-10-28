from flask import Flask

from .config import Config
from .views.main import bp as main_bp


def create_app(config_object: type[Config] | None = None) -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # Load configuration
    app.config.from_object(config_object or Config)

    # Secret key for sessions/flash
    app.secret_key = app.config.get("SECRET_KEY", "dev-only-secret")

    # Blueprints
    app.register_blueprint(main_bp)

    return app

