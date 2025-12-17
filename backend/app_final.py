"""ZKP-Based Web Authentication Backend - Production Version.

This file remains the entrypoint for `python app_final.py`, but the
implementation has been refactored into the `zkp_auth` package.
"""

from zkp_auth.app import create_app

app = create_app()


if __name__ == "__main__":
    app.run(debug=True, port=5000, host="0.0.0.0")
