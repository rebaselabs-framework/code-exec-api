"""HelpMiddleware — intercepts ?_help requests before they reach route handlers.

Zero overhead on normal requests: single dict-key check, then pass-through.
"""
from __future__ import annotations

import json
import re

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .extractor import extract_endpoint_help

__all__ = ["HelpMiddleware"]

_HELP_PARAM = "_help"


def _match_route(app: FastAPI, path: str, method: str) -> tuple["Route | None", str]:
    """Find the FastAPI route that matches path, preferring method match.

    Returns (route, matched_method). If no method match, returns the first
    route at that path with its primary method — per spec, ?_help works with
    any HTTP method and describes the endpoint regardless.
    """
    from fastapi import routing as fastapi_routing

    exact_match: fastapi_routing.APIRoute | None = None
    path_match: fastapi_routing.APIRoute | None = None
    path_match_method: str = method

    for route in app.routes:
        if not isinstance(route, fastapi_routing.APIRoute):
            continue

        # Try exact path match first
        is_exact = route.path == path
        if not is_exact:
            pattern = re.sub(r"\{[^}]+\}", r"[^/]+", route.path)
            pattern = f"^{pattern}$"
            is_exact = bool(re.match(pattern, path))

        if not is_exact:
            continue

        # Prefer a route where the method matches
        if method in (route.methods or set()):
            return route, method

        # Keep as fallback — use the route's primary method for help extraction
        if path_match is None:
            path_match = route
            # Use the first real method on this route (skip HEAD/OPTIONS)
            real_methods = [m for m in sorted(route.methods or []) if m not in ("HEAD", "OPTIONS")]
            path_match_method = real_methods[0] if real_methods else method

    if path_match is not None:
        return path_match, path_match_method

    return None, method


class HelpMiddleware(BaseHTTPMiddleware):
    """Middleware that intercepts _help requests and returns structured help.

    Usage::

        app = FastAPI()
        app.add_middleware(HelpMiddleware)

    Any endpoint immediately becomes self-describing via two methods:

        GET /api/transform?_help          # query param
        POST /api/transform?_help=true    # query param
        POST /api/transform               # body: {"_help": true}
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        # Fast path: check query param first (zero-cost for normal requests)
        is_help = _HELP_PARAM in request.query_params

        # Also support {"_help": true} in POST/PUT request body
        if not is_help and request.method.upper() in ("POST", "PUT", "PATCH"):
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                try:
                    raw_body = await request.body()
                    if raw_body:
                        body_data = json.loads(raw_body)
                        if body_data.get(_HELP_PARAM):
                            is_help = True
                        # Cache the body so the route handler can still read it
                        request._body = raw_body  # type: ignore[attr-defined]
                except (json.JSONDecodeError, Exception):
                    pass

        if not is_help:
            return await call_next(request)

        # Find the FastAPI app (may be wrapped)
        app = request.app
        # Unwrap to the root FastAPI app if there are sub-applications
        while hasattr(app, "app"):
            app = app.app

        path = request.url.path
        method = request.method.upper()

        route, matched_method = _match_route(app, path, method)

        if route is None:
            return JSONResponse(
                status_code=404,
                content={
                    "error": f"No route found at {path}",
                    "hint": "Try GET /_help for a list of all available endpoints",
                },
            )

        try:
            help_data = extract_endpoint_help(route, matched_method)
            return JSONResponse(
                status_code=200,
                content=help_data.model_dump(exclude_none=False),
                headers={"X-Help-Response": "true"},
            )
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                status_code=500,
                content={"error": f"Failed to generate help: {exc}"},
            )


# Type stub for call_next
from typing import Any  # noqa: E402
