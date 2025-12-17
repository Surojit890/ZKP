"""ZKP authentication backend package.

`create_app()` is exported for the entrypoint (app_final.py) and for tests.
"""

from .app import create_app

__all__ = ["create_app"]
