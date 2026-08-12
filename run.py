from dotenv import load_dotenv

load_dotenv()  # must happen before `from app import create_app` reads env-based config

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    # debug=True only ever comes from FLASK_ENV=development via config.py -
    # never hardcode it here, or it'll silently ship to production.
    app.run(debug=app.config["DEBUG"])
