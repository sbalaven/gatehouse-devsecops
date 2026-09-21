"""Local-only launcher. Containers use Waitress directly."""
import os
import secrets

from waitress import serve
from app import create_app

if __name__ == "__main__":
    if not os.environ.get("SECRET_KEY"):
        if os.environ.get("APP_ENV") == "production":
            raise SystemExit("Production requires an explicit SECRET_KEY.")
        os.environ["SECRET_KEY"] = secrets.token_urlsafe(48)
        print("Using a temporary local session key. Restarting signs everyone out.")
    print("Gatehouse is ready at http://127.0.0.1:8080", flush=True)
    serve(create_app(), host="127.0.0.1", port=8080, threads=4)
