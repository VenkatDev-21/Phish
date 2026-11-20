"""WSGI entry point for gunicorn and other production servers.

``app.py`` still owns every route; this module exists so the process manager
has one stable target (``wsgi:app``) instead of importing a script that also
contains a development ``app.run`` block.

Local development keeps using ``python app.py``.
"""

from app import app

__all__ = ["app"]
