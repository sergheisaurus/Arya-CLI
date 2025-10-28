# ARYA Viewer (Flask)

Refactored into a proper Flask package with blueprints, services, and templates.

## Structure

- `app.py` – simple launcher using the app factory
- `arya_web/` – Flask package
  - `config.py` – configuration (env overridable)
  - `services/` – Cognito auth + HTTP client helpers
  - `views/main.py` – routes blueprint
  - `templates/` – Jinja templates
- `arya_fetch.py` – interactive CLI client (unchanged)
- `arya_login.py` – SRP login to create `.arya_tokens.json`

## Setup

1. Create a virtualenv and install deps:
   
   ```bash
   pip install -r requirements.txt
   ```

2. Optional: create `login.json` with credentials to auto-login:
   
   ```json
   { "email": "you@example.com", "password": "..." }
   ```

3. Run the app:
   
   ```bash
   python app.py
   ```

The app listens on `http://127.0.0.1:5001`.

## Configuration

Environment variables (defaults shown):

- `SECRET_KEY=dev-only-secret`
- `ARYA_USER_POOL_ID=eu-central-1_sjczhcQCX`
- `ARYA_CLIENT_ID=at6lgqnsnrjtbhrl30s6knvns`
- `ARYA_REGION=eu-central-1`
- `ARYA_CLOUD_HOST=https://arya.spinetix.cloud`
- `ARYA_SERVICES_HOST=https://arya.services.spinetix.com`
- `ARYA_CACHE_PATH=.arya_tokens.json`
- `ARYA_LOGIN_FILE=login.json`

## Notes

- Tokens are cached in `.arya_tokens.json` (auto-refreshed). Keep it out of version control.
- The web app mirrors the previous single-file functionality (Dashboard, Accounts, Media list/detail) with improved structure.
